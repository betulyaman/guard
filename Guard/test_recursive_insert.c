#include "test_art.h"

// Under test
STATIC NTSTATUS recursive_insert(_Inout_opt_ ART_NODE* node,
    _Inout_ ART_NODE** ref,
    _In_ CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ ULONG value,
    _In_ USHORT depth,
    _Out_ PBOOLEAN old,
    _In_ BOOLEAN replace,
    _Out_ PULONG old_value);

// --- küçük yardımcılar (varsa mevcutlarını kullan) ---
// --- CRT'siz, kernel-safe uzunluk helper'ı ---
static USHORT t_cstr_len(_In_reads_or_z_(MAXUSHORT) const char* s)
{
    if (!s) return 0;
    USHORT n = 0;
    while (n < MAXUSHORT) {
        if (s[n] == '\0') break;
        ++n;
    }
    return n; // MAXUSHORT’a vurursa satürasyon gibi davranır
}

// --- strlen kullanmadan anahtar alloc/copy helper'ı ---
static PUCHAR ri_key(const char* s, USHORT* out_len)
{
    USHORT len = t_cstr_len(s);
    PUCHAR k = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
    if (!k) return NULL;
    if (len) RtlCopyMemory(k, s, len);
    if (out_len) *out_len = len;
    return k;
}

static VOID ri_free_key(PUCHAR k)
{
    if (k) ExFreePool2(k, ART_TAG, NULL, 0);
}

// Bir köke işaretçi döndür (NULL’la başlat)
static VOID ri_reset_root(ART_NODE** root) { *root = NULL; }

// =====================================================
// Test 1: Guard kontrolleri
// =====================================================
BOOLEAN test_recursive_insert_guards()
{
    TEST_START("recursive_insert: guards");

    reset_mock_state();

    ART_NODE* root = NULL;
    BOOLEAN old = TRUE; ULONG oldv = 0xAA;
    USHORT kl; PUCHAR k = ri_key("a", &kl);

    NTSTATUS st;

#pragma warning(push)
#pragma warning(disable: 6387)
    st = recursive_insert(NULL, NULL, k, kl, 0x11, 0, &old, TRUE, &oldv);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: ref=NULL reddedilmeli");

#pragma warning(push)
#pragma warning(disable: 6387)
    st = recursive_insert(NULL, &root, NULL, kl, 0x11, 0, &old, TRUE, &oldv);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: key=NULL reddedilmeli");

    st = recursive_insert(NULL, &root, k, kl, 0x11, 2 /*>len*/, &old, TRUE, &oldv);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: depth>key_length reddedilmeli");

#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_insert(NULL, &root, k, kl, 0x11, 0, NULL, TRUE, &oldv);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.4: old=NULL reddedilmeli");
    st = recursive_insert(NULL, &root, k, kl, 0x11, 0, &old, TRUE, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.5: old_value=NULL reddedilmeli");
#pragma warning(pop)

    ri_free_key(k);

    TEST_END("recursive_insert: guards");
    return TRUE;
}

// =====================================================
// Test 2: Boş slota yaprak ekleme (root=NULL)
// =====================================================
BOOLEAN test_recursive_insert_into_null_slot()
{
    TEST_START("recursive_insert: insert into NULL");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT kl; PUCHAR k = ri_key("abc", &kl);
    BOOLEAN old; ULONG oldv;

    NTSTATUS st = recursive_insert(NULL, &root, k, kl, 0x1111, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "2.1: NULL slota ekleme basarili olmali");
    TEST_ASSERT(root != NULL && IS_LEAF(root), "2.2: root artik yaprak olmali");

    ART_LEAF* lf = LEAF_RAW(root);
    TEST_ASSERT(lf->value == 0x1111 && lf->key_length == kl, "2.3: yaprak icerigi dogru");
    TEST_ASSERT(!old && oldv == POLICY_NONE, "2.4: old=false, old_value=POLICY_NONE");

    // cleanup
    free_leaf(&lf); root = NULL;
    ri_free_key(k);

    TEST_END("recursive_insert: insert into NULL");
    return TRUE;
}

// =====================================================
// Test 3: Dupe: replace=FALSE değer korunmalı
// =====================================================
BOOLEAN test_recursive_insert_duplicate_no_replace()
{
    TEST_START("recursive_insert: duplicate no-replace");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT kl; PUCHAR k = ri_key("hello", &kl);
    BOOLEAN old; ULONG oldv;

    // first insert
    NTSTATUS st = recursive_insert(NULL, &root, k, kl, 0xA1, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: ilk ekleme basarili");
    // duplicate, no replace
    st = recursive_insert(root, &root, k, kl, 0xB2, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "3.2: dupe ekleme basarili donmeli");
    TEST_ASSERT(old && oldv == 0xA1, "3.3: old=true ve eski deger dondurulmeli");

    // value degismemis olmali
    ART_LEAF* lf = LEAF_RAW(root);
    TEST_ASSERT(lf->value == 0xA1, "3.4: replace=FALSE => deger degismez");

    // cleanup
    free_leaf(&lf); root = NULL;
    ri_free_key(k);

    TEST_END("recursive_insert: duplicate no-replace");
    return TRUE;
}

// =====================================================
// Test 4: Dupe: replace=TRUE değeri günceller
// =====================================================
BOOLEAN test_recursive_insert_duplicate_with_replace()
{
    TEST_START("recursive_insert: duplicate with replace");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT kl; PUCHAR k = ri_key("world", &kl);
    BOOLEAN old; ULONG oldv;

    NTSTATUS st = recursive_insert(NULL, &root, k, kl, 0x10, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: ilk ekleme");
    st = recursive_insert(root, &root, k, kl, 0x20, 0, &old, TRUE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "4.2: dupe replace ekleme");
    TEST_ASSERT(old && oldv == 0x10, "4.3: eski deger raporlanmali");

    ART_LEAF* lf = LEAF_RAW(root);
    TEST_ASSERT(lf->value == 0x20, "4.4: replace=TRUE => yeni deger yazilmali");

    free_leaf(&lf); root = NULL;
    ri_free_key(k);

    TEST_END("recursive_insert: duplicate with replace");
    return TRUE;
}

// =====================================================
// Test 5: Yaprak bölme – ortadan ayrışma
//   "abX" vs "abY" depth=0 , lcp=2, NODE4 oluşur, iki edge: 'X' ve 'Y'
// =====================================================
BOOLEAN test_recursive_insert_split_leaf_diverge_middle()
{
    TEST_START("recursive_insert: split leaf diverge middle");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT k1l, k2l;
    PUCHAR k1 = ri_key("abX", &k1l);
    PUCHAR k2 = ri_key("abY", &k2l);
    BOOLEAN old; ULONG oldv;

    NTSTATUS st = recursive_insert(NULL, &root, k1, k1l, 0x11, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: ilk anahtar eklendi (yaprak)");
    st = recursive_insert(root, &root, k2, k2l, 0x22, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "5.2: ikinci anahtar eklenince split olmali");

    TEST_ASSERT(root && !IS_LEAF(root) && root->type == NODE4, "5.3: root NODE4 olmali");

    // NODE4 altında 'X' ve 'Y' kenarlari olmali
    ART_NODE4* n4 = (ART_NODE4*)root;
    ART_NODE** chX = find_child((ART_NODE*)n4, 'X');
    ART_NODE** chY = find_child((ART_NODE*)n4, 'Y');
    TEST_ASSERT(chX && *chX && IS_LEAF(*chX), "5.4: X kenari var ve yaprak");
    TEST_ASSERT(chY && *chY && IS_LEAF(*chY), "5.5: Y kenari var ve yaprak");

    ART_LEAF* lfX = LEAF_RAW(*chX);
    ART_LEAF* lfY = LEAF_RAW(*chY);
    TEST_ASSERT(lfX->value == 0x11 && lfY->value == 0x22, "5.6: degerler dogru");

    // cleanup (replace rd_free_tree)
    {
        ART_TREE t = { 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &root, &leafs, &nodes, 0);
        root = NULL;
    }

    ri_free_key(k1); ri_free_key(k2);

    TEST_END("recursive_insert: split leaf diverge middle");
    return TRUE;
}

// =====================================================
// Test 6: Yaprak bölme – prefix durumu (terminator 0x00 kenarı)
//   "ab" ile "abX" (depth=0) , lcp=2, kenarlar: 0x00 ve 'X'
// =====================================================
BOOLEAN test_recursive_insert_split_leaf_prefix_case()
{
    TEST_START("recursive_insert: split leaf prefix/terminator");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT k1l, k2l;
    PUCHAR k1 = ri_key("ab", &k1l);
    PUCHAR k2 = ri_key("abX", &k2l);
    BOOLEAN old; ULONG oldv;

    NTSTATUS st = recursive_insert(NULL, &root, k1, k1l, 0xA, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: 'ab' eklendi");
    st = recursive_insert(root, &root, k2, k2l, 0xB, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "6.2: 'abX' eklenince split olmali");

    ART_NODE4* n4 = (ART_NODE4*)root;
    TEST_ASSERT(n4->base.type == NODE4, "6.3: root NODE4");

    ART_NODE** term = find_child((ART_NODE*)n4, 0);
    ART_NODE** chX = find_child((ART_NODE*)n4, 'X');
    TEST_ASSERT(term && *term && IS_LEAF(*term), "6.4: terminator (0x00) yaprak olmali");
    TEST_ASSERT(chX && *chX && IS_LEAF(*chX), "6.5: 'X' yaprak olmali");

    ART_LEAF* lfA = LEAF_RAW(*term);
    ART_LEAF* lfB = LEAF_RAW(*chX);
    TEST_ASSERT(lfA->value == 0xA && lfB->value == 0xB, "6.6: degerler dogru");

    // cleanup: replace rd_free_tree
    {
        ART_TREE t = (ART_TREE){ 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &root, &leafs, &nodes, 0);
        root = NULL;
    }
    ri_free_key(k1); ri_free_key(k2);

    TEST_END("recursive_insert: split leaf prefix/terminator");
    return TRUE;
}

// =====================================================
// Test 7: İç düğüm prefix’i tamamen eşleşir , derine in, yeni çocuk ekle
// =====================================================
BOOLEAN test_recursive_insert_internal_full_prefix_then_descend()
{
    TEST_START("recursive_insert: internal full prefix then descend");

    reset_mock_state();

    // root NODE4, prefix="ab", çocuk altında 'c' yaprağı olsun
    ART_NODE4* root = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(root != NULL, "7-pre: root alloc");
    root->base.type = NODE4; root->base.num_of_child = 0;
    root->base.prefix_length = 2;
    root->base.prefix[0] = 'a'; root->base.prefix[1] = 'b';

    // var olan anahtar "ab" + "c"
    UCHAR kc[3] = { 'a','b','c' };
    ART_LEAF* lc = make_leaf(kc, 3, 0x11); TEST_ASSERT(lc, "7-pre: leaf c");
    (void)add_child4(root, (ART_NODE**)&root, 'c', SET_LEAF(lc));

    ART_NODE* ref = (ART_NODE*)root;

    // yeni anahtar "ab" + "d"
    UCHAR kd[3] = { 'a','b','d' };
    BOOLEAN old; ULONG oldv;
    NTSTATUS st = recursive_insert((ART_NODE*)root, &ref, kd, 3, 0x22, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: ekleme basarili");
    TEST_ASSERT(ref == (ART_NODE*)root, "7.2: ref degismemeli");

    ART_NODE** chd = find_child((ART_NODE*)root, 'd');
    TEST_ASSERT(chd && *chd && IS_LEAF(*chd), "7.3: 'd' yapragi eklendi");

    // cleanup: replace rd_free_tree
    {
        ART_TREE t = (ART_TREE){ 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &ref, &leafs, &nodes, 0);
        ref = NULL;
    }

    TEST_END("recursive_insert: internal full prefix then descend");
    return TRUE;
}

// =====================================================
// Test 8: İç düğüm prefix mismatch , prefix split, NODE4 üstte
// =====================================================
BOOLEAN test_recursive_insert_internal_prefix_mismatch_split()
{
    TEST_START("recursive_insert: internal prefix mismatch -> split");

    reset_mock_state();

    // root prefix="ab", sadece 'c' altında bir yaprak
    ART_NODE4* root = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(root, "8-pre: root");
    root->base.type = NODE4; root->base.num_of_child = 0;
    root->base.prefix_length = 2;
    root->base.prefix[0] = 'a'; root->base.prefix[1] = 'b';

    UCHAR kc[3] = { 'a','b','c' };
    ART_LEAF* lc = make_leaf(kc, 3, 0x10); TEST_ASSERT(lc, "8-pre: leaf c");
    (void)add_child4(root, (ART_NODE**)&root, 'c', SET_LEAF(lc));

    ART_NODE* ref = (ART_NODE*)root;

    // yeni anahtar "ax..." , prefix mismatch: 'a' eşit, ikinci bayt 'b' vs 'x'
    UCHAR kx[3] = { 'a','x','z' };
    BOOLEAN old; ULONG oldv;
    NTSTATUS st = recursive_insert((ART_NODE*)root, &ref, kx, 3, 0x99, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: ekleme basarili olmali");
    TEST_ASSERT(ref && ref->type == NODE4, "8.2: split sonrasi ust NODE4 olmali");

    // Yeni ağacın altında dallar: 'b' (eski root’a giden) ve 'x' (yeni yaprak)
    ART_NODE4* n4 = (ART_NODE4*)ref;
    ART_NODE** ch_b = find_child((ART_NODE*)n4, 'b');
    ART_NODE** ch_x = find_child((ART_NODE*)n4, 'x');
    TEST_ASSERT(ch_b && *ch_b && !IS_LEAF(*ch_b), "8.3: 'b' alti eski alt agac");
    TEST_ASSERT(ch_x && *ch_x && IS_LEAF(*ch_x), "8.4: 'x' alti yeni yaprak");

    // cleanup: replace rd_free_tree
    {
        ART_TREE t = (ART_TREE){ 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &ref, &leafs, &nodes, 0);
        ref = NULL;
    }

    TEST_END("recursive_insert: internal prefix mismatch -> split");
    return TRUE;
}

// =====================================================
// Test 9: Prefix yokken (node->prefix_length=0) depth==key_len
//         terminator (0x00) kenarıyla ekleme/güncelleme
// =====================================================
BOOLEAN test_recursive_insert_terminator_no_prefix_path()
{
    TEST_START("recursive_insert: terminator on no-prefix path");

    reset_mock_state();

    // Basit NODE4, hic cocuk yok
    ART_NODE4* root = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(root, "9-pre: root");
    root->base.type = NODE4; root->base.num_of_child = 0; root->base.prefix_length = 0;

    ART_NODE* ref = (ART_NODE*)root;

    // Boş-string anahtar gibi davran: depth==key_length==0
    BOOLEAN old; ULONG oldv;
    NTSTATUS st = recursive_insert((ART_NODE*)root, &ref, (PUCHAR)"", 0, 0x55, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: terminator ile ekleme basarili");

    ART_NODE** term = find_child((ART_NODE*)ref, 0);
    TEST_ASSERT(term && *term && IS_LEAF(*term), "9.2: terminator yaprak eklenmis");

    // ikinci kez replace
    st = recursive_insert((ART_NODE*)ref, &ref, (PUCHAR)"", 0, 0x66, 0, &old, TRUE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st) && old && oldv == 0x55, "9.3: replace terminator degeri");
    ART_LEAF* lf = LEAF_RAW(*term);
    TEST_ASSERT(lf->value == 0x66, "9.4: guncel deger 0x66");

    // cleanup: replace rd_free_tree
    {
        ART_TREE t = (ART_TREE){ 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &ref, &leafs, &nodes, 0);
        ref = NULL;
    }

    TEST_END("recursive_insert: terminator on no-prefix path");
    return TRUE;
}

// =====================================================
// Test 10: Split/expand sırasında *ref güncellenmeli (root bölünmesi)
//   tek yaprak -> ikinci anahtar eklenince iç düğüm yayımlanır
// =====================================================
BOOLEAN test_recursive_insert_updates_ref_on_split()
{
    TEST_START("recursive_insert: updates ref on split");

    reset_mock_state();

    ART_NODE* root = NULL;
    USHORT k1l, k2l;
    PUCHAR k1 = ri_key("cat", &k1l);
    PUCHAR k2 = ri_key("car", &k2l);
    BOOLEAN old; ULONG oldv;

    NTSTATUS st = recursive_insert(NULL, &root, k1, k1l, 0x01, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "10.1: ilk ekleme");
    TEST_ASSERT(IS_LEAF(root), "10.2: root su an yaprak");

    st = recursive_insert(root, &root, k2, k2l, 0x02, 0, &old, FALSE, &oldv);
    TEST_ASSERT(NT_SUCCESS(st), "10.3: ikinci ekleme (split)");
    TEST_ASSERT(root && !IS_LEAF(root) && root->type == NODE4, "10.4: root artik ic dugum");

    // her iki key de erişilebilir olmalı
    ART_NODE** ch_t = find_child(root, 't');
    ART_NODE** ch_r = find_child(root, 'r');
    TEST_ASSERT(ch_t && *ch_t && IS_LEAF(*ch_t), "10.5: 't' yaprak var");
    TEST_ASSERT(ch_r && *ch_r && IS_LEAF(*ch_r), "10.6: 'r' yaprak var");

    // cleanup: replace rd_free_tree
    {
        ART_TREE t = (ART_TREE){ 0 };
        ULONG leafs = 0, nodes = 0;
        (void)recursive_delete_all_internal(&t, &root, &leafs, &nodes, 0);
        root = NULL;
    }
    ri_free_key(k1); ri_free_key(k2);

    TEST_END("recursive_insert: updates ref on split");
    return TRUE;
}

// ------------------------------------------------------------------
// ADD: Test 11 — invalid internal type is rejected
// ------------------------------------------------------------------
BOOLEAN test_recursive_insert_invalid_internal_type()
{
    TEST_START("recursive_insert: invalid internal type");

    reset_mock_state();

    ART_NODE* bad = t_alloc_header_only((NODE_TYPE)0x77);
    TEST_ASSERT(bad != NULL, "11-pre: alloc bad header");

    USHORT kl; PUCHAR k = ri_key("a", &kl);
    BOOLEAN old = FALSE; ULONG oldv = 0;
    ART_NODE* ref = bad;

    NTSTATUS st = recursive_insert(bad, &ref, k, kl, 0x01, 0, &old, FALSE, &oldv);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "11.1: invalid type must be rejected");
    TEST_ASSERT(ref == bad, "11.2: ref unchanged");

    t_free(bad);
    ri_free_key(k);

    TEST_END("recursive_insert: invalid internal type");
    return TRUE;
}

// ------------------------------------------------------------------
// ADD: Test 12 — corrupt child count is rejected (e.g., NODE4 with 5)
// ------------------------------------------------------------------
BOOLEAN test_recursive_insert_corrupt_child_count()
{
    TEST_START("recursive_insert: corrupt child count");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4();
    TEST_ASSERT(n4 != NULL, "12-pre: node4 alloc");
    n4->base.type = NODE4;
    n4->base.num_of_child = 5; // corrupt (>4)

    USHORT kl; PUCHAR k = ri_key("x", &kl);
    BOOLEAN old = FALSE; ULONG oldv = 0;
    ART_NODE* ref = (ART_NODE*)n4;

    NTSTATUS st = recursive_insert((ART_NODE*)n4, &ref, k, kl, 0x02, 0, &old, FALSE, &oldv);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "12.1: child count corruption must be rejected");
    TEST_ASSERT(ref == (ART_NODE*)n4, "12.2: ref unchanged on reject");

    t_free(n4);
    ri_free_key(k);

    TEST_END("recursive_insert: corrupt child count");
    return TRUE;
}

// ------------------------------------------------------------------
// ADD: Test 13 — key_length > MAX_KEY_LENGTH => INVALID_PARAMETER
// (yalnızca derleme zamanı koşulu uygunsa çalışır)
// ------------------------------------------------------------------
BOOLEAN test_recursive_insert_key_too_long()
{
    TEST_START("recursive_insert: key too long");

#if (MAX_KEY_LENGTH < MAXUSHORT)
    reset_mock_state();

    USHORT too_long = (USHORT)(MAX_KEY_LENGTH + 1u);
    PUCHAR k = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, too_long, ART_TAG);
    TEST_ASSERT(k != NULL, "13-pre: key alloc");
    // doldur
    for (USHORT i = 0; i < too_long; ++i) k[i] = (UCHAR)i;

    ART_NODE* root = NULL;
    BOOLEAN old = FALSE; ULONG oldv = 0;

    NTSTATUS st = recursive_insert(NULL, &root, k, too_long, 0xCAFE, 0, &old, FALSE, &oldv);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "13.1: key too long must be rejected");
    TEST_ASSERT(root == NULL, "13.2: root must remain NULL");

    ExFreePool2(k, ART_TAG, NULL, 0);
#else
    LOG_MSG("[SKIP] 13: MAX_KEY_LENGTH == MAXUSHORT; cannot form too-long key in USHORT param\n");
#endif

    TEST_END("recursive_insert: key too long");
    return TRUE;
}

// =================== Suite runner (append new tests) ===================
NTSTATUS run_all_recursive_insert_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting recursive_insert() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN ok = TRUE;

    if (!test_recursive_insert_guards())                              ok = FALSE; // 1
    if (!test_recursive_insert_into_null_slot())                      ok = FALSE; // 2
    if (!test_recursive_insert_duplicate_no_replace())                ok = FALSE; // 3
    if (!test_recursive_insert_duplicate_with_replace())              ok = FALSE; // 4
    if (!test_recursive_insert_split_leaf_diverge_middle())           ok = FALSE; // 5
    if (!test_recursive_insert_split_leaf_prefix_case())              ok = FALSE; // 6
    if (!test_recursive_insert_internal_full_prefix_then_descend())   ok = FALSE; // 7
    if (!test_recursive_insert_internal_prefix_mismatch_split())      ok = FALSE; // 8
    if (!test_recursive_insert_terminator_no_prefix_path())           ok = FALSE; // 9
    if (!test_recursive_insert_updates_ref_on_split())                ok = FALSE; // 10
    if (!test_recursive_insert_invalid_internal_type())               ok = FALSE; // 11 (NEW)
    if (!test_recursive_insert_corrupt_child_count())                 ok = FALSE; // 12 (NEW)
    if (!test_recursive_insert_key_too_long())                        ok = FALSE; // 13 (NEW)

    LOG_MSG("\n========================================\n");
    if (ok) LOG_MSG("ALL recursive_insert() TESTS PASSED!\n");
    else    LOG_MSG("SOME recursive_insert() TESTS FAILED!\n");
    LOG_MSG("========================================\n\n");

    return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}