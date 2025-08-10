#include "test_art.h"

// SUT
NTSTATUS art_delete_subtree(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

// ---------- small local helpers (no CRT) ----------
static VOID ds_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* ds_make_n4(void) { return (ART_NODE4*)art_create_node(NODE4); }
static ART_NODE16* ds_make_n16(void) { return (ART_NODE16*)art_create_node(NODE16); }
static ART_NODE48* ds_make_n48(void) { return (ART_NODE48*)art_create_node(NODE48); }
static ART_NODE256* ds_make_n256(void) { return (ART_NODE256*)art_create_node(NODE256); }

static BOOLEAN ds_n4_set(ART_NODE4* n4, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n4 || !keys || !ch || cnt > 4) return FALSE;
    ds_zero(n4->keys, sizeof(n4->keys));
    ds_zero(n4->children, sizeof(n4->children));
    for (USHORT i = 0; i < cnt; i++) { n4->keys[i] = keys[i]; n4->children[i] = ch[i]; }
    n4->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN ds_n16_set(ART_NODE16* n16, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n16 || !keys || !ch || cnt > 16) return FALSE;
    ds_zero(n16->keys, sizeof(n16->keys));
    ds_zero(n16->children, sizeof(n16->children));
    for (USHORT i = 0; i < cnt; i++) { n16->keys[i] = keys[i]; n16->children[i] = ch[i]; }
    n16->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN ds_n48_map(ART_NODE48* n48, const UCHAR* key_bytes, USHORT cnt, ART_NODE* const* ch)
{
    if (!n48 || !key_bytes || !ch || cnt > 48) return FALSE;
    ds_zero(n48->child_index, sizeof(n48->child_index));
    ds_zero(n48->children, sizeof(n48->children));
    for (USHORT i = 0; i < cnt; i++) { n48->children[i] = ch[i]; n48->child_index[key_bytes[i]] = (UCHAR)(i + 1); }
    n48->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN ds_n256_set(ART_NODE256* n256, const UCHAR* idx, USHORT cnt, ART_NODE* const* ch)
{
    if (!n256 || !idx || !ch || cnt > 256) return FALSE;
    ds_zero(n256->children, sizeof(n256->children));
    for (USHORT i = 0; i < cnt; i++) { n256->children[idx[i]] = ch[i]; }
    n256->base.num_of_child = cnt;
    return TRUE;
}

// ===============================
// Test 1: Guard conditions
// ===============================
BOOLEAN test_ads_guard_params()
{
    TEST_START("art_delete_subtree: guard params");

    UNICODE_STRING u; ds_zero(&u, sizeof(u));
    NTSTATUS st;

#pragma warning(push)
#pragma warning(disable: 6387)
    st = art_delete_subtree(NULL, &u);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL tree -> STATUS_INVALID_PARAMETER");

    ART_TREE t; ds_zero(&t, sizeof(t));
#pragma warning(push)
#pragma warning(disable: 6387)
    st = art_delete_subtree(&t, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL key -> STATUS_INVALID_PARAMETER");

    TEST_END("art_delete_subtree: guard params");
    return TRUE;
}

// ===============================
// Test 2: Empty tree
// ===============================
BOOLEAN test_ads_empty_tree()
{
    TEST_START("art_delete_subtree: empty tree");

    ART_TREE t; ds_zero(&t, sizeof(t));
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING wkey;
    create_unicode_string(&wkey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &wkey);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "2.1: empty tree -> STATUS_NOT_FOUND");

    cleanup_unicode_string(&wkey);
    TEST_END("art_delete_subtree: empty tree");
    return TRUE;
}

// ===============================
// Test 3: Empty prefix (Length==0)
// ===============================
BOOLEAN test_ads_empty_prefix()
{
    TEST_START("art_delete_subtree: empty prefix key");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.size = 1; // pretend non-empty, but key is empty -> invalid
    WCHAR wempty[] = L"";
    UNICODE_STRING k; create_unicode_string(&k, wempty, 0);

    NTSTATUS st = art_delete_subtree(&t, &k);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "3.1: empty unicode key -> STATUS_INVALID_PARAMETER");

    cleanup_unicode_string(&k);
    TEST_END("art_delete_subtree: empty prefix key");
    return TRUE;
}

// ===============================
// Test 4: Prefix not found (missing child)
// ===============================
BOOLEAN test_ads_prefix_not_found_branch()
{
    TEST_START("art_delete_subtree: prefix not found (missing child)");

    // Build root NODE4 with only child 'b'-> leaf "b"
    ART_NODE4* root = ds_make_n4();
    TEST_ASSERT(root != NULL, "4-pre: root NODE4 allocated");
    UCHAR kB = 'b';
    ART_LEAF* lb = make_leaf(&kB, 1, 0xB);
    TEST_ASSERT(lb != NULL, "4-pre: leaf 'b' allocated");
    ART_NODE* ch = (ART_NODE*)SET_LEAF(lb);
    UCHAR key = 'b';
    TEST_ASSERT(ds_n4_set(root, &key, 1, &ch), "4-pre: root wired");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 1;

    // ask to delete subtree "a" -> not found
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "4.1: prefix 'a' not found");

    // cleanup (root tree still intact)
    free_node((ART_NODE**)&root); // this frees node only; free leaf too
    if (lb) { free_leaf(&lb); }   // since we didn't run delete_all
    t.root = NULL; t.size = 0;

    cleanup_unicode_string(&ukey);
    TEST_END("art_delete_subtree: prefix not found (missing child)");
    return TRUE;
}

// ===============================
// Test 5: Prefix mismatch at node prefix
// ===============================
BOOLEAN test_ads_prefix_mismatch_at_prefix()
{
    TEST_START("art_delete_subtree: prefix mismatch (node prefix)");

    // Root NODE4 with a stored prefix "ab" (2), then child under key 'c'
    ART_NODE4* root = ds_make_n4();
    TEST_ASSERT(root != NULL, "5-pre: root NODE4 allocated");

    root->base.prefix_length = 2;
    root->base.prefix[0] = 'a';
    root->base.prefix[1] = 'b';

    UCHAR kc = 'c';
    ART_LEAF* lc = make_leaf(&kc, 1, 0xCC);
    TEST_ASSERT(lc != NULL, "5-pre: leaf 'c' allocated");
    ART_NODE* ch = (ART_NODE*)SET_LEAF(lc);
    TEST_ASSERT(ds_n4_set(root, &kc, 1, &ch), "5-pre: child wired under 'c'");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 1;

    // ask to delete subtree with prefix "ax" -> mismatches at 'b' vs 'x'
    WCHAR wkey_buf[] = L"ax";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "5.1: prefix mismatch -> STATUS_NOT_FOUND");

    // cleanup
    free_node((ART_NODE**)&root);
    if (lc) { free_leaf(&lc); }
    t.root = NULL; t.size = 0;

    cleanup_unicode_string(&ukey);
    TEST_END("art_delete_subtree: prefix mismatch (node prefix)");
    return TRUE;
}

// ===============================
// Test 6: Delete exact leaf by prefix
// ===============================
BOOLEAN test_ads_delete_exact_leaf()
{
    TEST_START("art_delete_subtree: delete exact leaf");

    // Build root NODE4: child 'a' -> leaf "a"
    ART_NODE4* root = ds_make_n4();
    TEST_ASSERT(root != NULL, "6-pre: root NODE4 allocated");
    UCHAR ka = 'a';
    ART_LEAF* la = make_leaf(&ka, 1, 0x11);
    TEST_ASSERT(la != NULL, "6-pre: leaf 'a' allocated");
    ART_NODE* ch = (ART_NODE*)SET_LEAF(la);
    TEST_ASSERT(ds_n4_set(root, &ka, 1, &ch), "6-pre: wired");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 1;

    // delete subtree "a" -> should remove leaf and collapse from parent
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: success");
    TEST_ASSERT(t.root == NULL, "6.2: root cleared");
    TEST_ASSERT(t.size == 0, "6.3: size decremented by 1");

    cleanup_unicode_string(&ukey);
    // nothing left to free; la freed by art_delete_subtree path
    TEST_END("art_delete_subtree: delete exact leaf");
    return TRUE;
}

// ===============================
// Test 7: Delete entire internal subtree under NODE4 parent
// ===============================
BOOLEAN test_ads_delete_internal_subtree_node4()
{
    TEST_START("art_delete_subtree: delete internal subtree (NODE4 parent)");

    // root (NODE4) has two branches: 'a' -> small subtree; 'z' -> leaf
    ART_NODE4* root = ds_make_n4();
    TEST_ASSERT(root != NULL, "7-pre: root NODE4 allocated");

    // branch 'a' : NODE16 with two leaves
    ART_NODE16* a_int = ds_make_n16();
    TEST_ASSERT(a_int != NULL, "7-pre: NODE16 under 'a'");

    UCHAR kx[2] = { 1, 2 };
    UCHAR lv0 = 1, lv1 = 2;
    ART_LEAF* l0 = make_leaf(&lv0, 1, 0xA0);
    ART_LEAF* l1 = make_leaf(&lv1, 1, 0xA1);
    TEST_ASSERT(l0 && l1, "7-pre: leaves under NODE16");
    ART_NODE* a_ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(ds_n16_set(a_int, kx, 2, a_ch), "7-pre: NODE16 wired");

    // branch 'z' : a single leaf
    UCHAR kz = 'z';
    ART_LEAF* lz = make_leaf(&kz, 1, 0xFFFFFFFF);
    TEST_ASSERT(lz != NULL, "7-pre: leaf 'z'");
    ART_NODE* zchild = (ART_NODE*)SET_LEAF(lz);

    UCHAR rkeys[2] = { 'a', 'z' };
    ART_NODE* rch[2] = { (ART_NODE*)a_int, zchild };
    TEST_ASSERT(ds_n4_set(root, rkeys, 2, rch), "7-pre: root wired");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 3; // 2 leaves in 'a' subtree + 1 leaf 'z'

    // Delete subtree prefix "a" -> remove 2 keys, 'z' kalır
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: success");
    TEST_ASSERT(t.root != NULL, "7.2: root still present (z branch remains)");
    TEST_ASSERT(t.size == 1, "7.3: size decremented exactly by deleted keys (now 1)");

    // cleanup: delete remaining subtree
    if (t.root) {
        ULONG dummyL = 0, dummyN = 0;
        (void)recursive_delete_all_internal(&t, t.root, &dummyL, &dummyN, 0);
        t.root = NULL; t.size = 0;
    }
    cleanup_unicode_string(&ukey);
    TEST_END("art_delete_subtree: delete internal subtree (NODE4 parent)");
    return TRUE;
}

// ===============================
// Test 8: Delete entire internal subtree when target is the ROOT
// ===============================
BOOLEAN test_ads_delete_root_subtree()
{
    TEST_START("art_delete_subtree: delete root subtree");

    // root is internal (NODE48) with two leaves; prefix equals depth after prefix check
    ART_NODE48* root = ds_make_n48();
    TEST_ASSERT(root != NULL, "8-pre: root NODE48");

    UCHAR map[2] = { 'x', 'y' };
    ART_LEAF* lx = make_leaf(&map[0], 1, 0x10);
    ART_LEAF* ly = make_leaf(&map[1], 1, 0x20);
    TEST_ASSERT(lx && ly, "8-pre: leaves");
    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(lx), (ART_NODE*)SET_LEAF(ly) };
    TEST_ASSERT(ds_n48_map(root, map, 2, ch), "8-pre: mapped");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 2;

    // prefix == "" is invalid; instead use a prefix that matches at depth 0 by
    // immediately taking the delete-all branch ONLY when depth == prefix_len.
    // Make prefix length 0? the function rejects empty prefix earlier.
    // So use "x" to delete the subtree reached via 'x' at depth 1,
    // but to delete entire root we need exact match at the current node before taking child.
    // Achieve that by giving root a stored prefix equal to "x" and prefix_len=1; then query "x".
    root->base.prefix_length = 1;
    root->base.prefix[0] = 'x';

    WCHAR wkey_buf[] = L"x";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: success");
    TEST_ASSERT(t.root == NULL, "8.2: root cleared");

    cleanup_unicode_string(&ukey);
    TEST_END("art_delete_subtree: delete root subtree");
    return TRUE;
}

// ===============================
// Test 9: Delete internal subtree under NODE256 parent
// ===============================
BOOLEAN test_ads_delete_internal_subtree_node256_parent()
{
    TEST_START("art_delete_subtree: delete internal subtree (NODE256 parent)");

    ART_NODE256* root = ds_make_n256();
    TEST_ASSERT(root != NULL, "9-pre: NODE256 root");

    // child under index 'a' -> NODE4 with a leaf; plus another child under index 'q'
    ART_NODE4* a_int = ds_make_n4();
    TEST_ASSERT(a_int != NULL, "9-pre: child NODE4 under 'a'");

    UCHAR kv = 1;
    ART_LEAF* lv = make_leaf(&kv, 1, 0x77);
    TEST_ASSERT(lv != NULL, "9-pre: leaf under 'a' subtree");
    ART_NODE* a_leaf = (ART_NODE*)SET_LEAF(lv);
    UCHAR inner_key = kv;
    TEST_ASSERT(ds_n4_set(a_int, &inner_key, 1, &a_leaf), "9-pre: a_int wired");

    UCHAR idxs[2] = { 'a', 'q' };
    ART_LEAF* lq = make_leaf(&idxs[1], 1, 0x99);
    TEST_ASSERT(lq != NULL, "9-pre: leaf 'q'");
    ART_NODE* top_children[2] = { (ART_NODE*)a_int, (ART_NODE*)SET_LEAF(lq) };
    TEST_ASSERT(ds_n256_set(root, idxs, 2, top_children), "9-pre: root wired");

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 2; // 2 keys total

    // delete subtree "a" -> remove 1 key; 'q' kalır
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: success");
    TEST_ASSERT(t.root != NULL, "9.2: root remains");
    TEST_ASSERT(t.size == 1, "9.3: size decremented exactly by 1");

    // Cleanup remaining
    if (t.root) {
        ULONG dummyL = 0, dummyN = 0;
        (void)recursive_delete_all_internal(&t, t.root, &dummyL, &dummyN, 0);
        t.root = NULL; t.size = 0;
    }
    cleanup_unicode_string(&ukey);

    TEST_END("art_delete_subtree: delete internal subtree (NODE256 parent)");
    return TRUE;
}

// ===============================
// Test 10: Deep chain – recursion overflows, fallback succeeds
// ===============================
BOOLEAN test_ads_fallback_on_overflow_success()
{
    TEST_START("art_delete_subtree: fallback succeeds on deep overflow");

    // Build deep chain: NODE4 -> NODE4 -> ... -> leaf
    ART_NODE* cur = (ART_NODE*)ds_make_n4();
    TEST_ASSERT(cur != NULL, "10-pre: first NODE4");
    ART_NODE* root = cur;

    const UCHAR step_key = 'a';

    for (USHORT i = 0; i < (USHORT)(MAX_RECURSION_DEPTH + 2); i++) {
        ART_NODE4* n4 = (ART_NODE4*)cur;
        ART_NODE* next;
        if (i == (USHORT)(MAX_RECURSION_DEPTH + 1)) {
            UCHAR lfkb = 'x';
            ART_LEAF* lf = make_leaf(&lfkb, 1, 0x55);
            TEST_ASSERT(lf != NULL, "10-pre: tail leaf");
            next = (ART_NODE*)SET_LEAF(lf);
        }
        else {
            next = (ART_NODE*)ds_make_n4();
            TEST_ASSERT(next != NULL, "10-pre: intermediate NODE4");
        }
        UCHAR k = step_key;
        ART_NODE* child = next;
        TEST_ASSERT(ds_n4_set(n4, &k, 1, &child), "10-pre: link step");
        if (!IS_LEAF(next)) cur = next;
    }

    ART_TREE t; ds_zero(&t, sizeof(t));
    t.root = root;
    t.size = 1; // exactly one key

    // Delete prefix "a" , overflow in recursive delete_all, fallback iteratif çalışır
    WCHAR wkey_buf[] = L"a";
    UNICODE_STRING ukey; create_unicode_string(&ukey, wkey_buf, STRW_LITERAL_LEN(wkey_buf));

    NTSTATUS st = art_delete_subtree(&t, &ukey);
    TEST_ASSERT(NT_SUCCESS(st), "10.1: fallback handled overflow and succeeded");
    TEST_ASSERT(t.root == NULL, "10.2: root cleared after subtree deletion");
    TEST_ASSERT(t.size == 0, "10.3: size decremented exactly by deleted key (now 0)");

    cleanup_unicode_string(&ukey);
    TEST_END("art_delete_subtree: fallback succeeds on deep overflow");
    return TRUE;
}


// ===============================
// Suite runner
// ===============================
NTSTATUS run_all_art_delete_subtree_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting art_delete_subtree() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_ads_guard_params())                           all = FALSE; // (1)
    if (!test_ads_empty_tree())                             all = FALSE; // (2)
    if (!test_ads_empty_prefix())                           all = FALSE; // (3)
    if (!test_ads_prefix_not_found_branch())                all = FALSE; // (4)
    if (!test_ads_prefix_mismatch_at_prefix())              all = FALSE; // (5)
    if (!test_ads_delete_exact_leaf())                      all = FALSE; // (6)
    if (!test_ads_delete_internal_subtree_node4())          all = FALSE; // (7)
    if (!test_ads_delete_internal_subtree_node256_parent()) all = FALSE; // (9)
    if (!test_ads_fallback_on_overflow_success())           all = FALSE; // (10)

    DbgPrint("\n========================================\n");
    if (all) {
        DbgPrint("ALL art_delete_subtree() TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME art_delete_subtree() TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
