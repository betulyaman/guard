#if UNIT_TEST

#include "test_art.h"

// SUT
STATIC BOOLEAN prefix_compare(_In_ CONST ART_NODE* node,
    _In_reads_bytes_(key_length) CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ USHORT depth,
    _In_opt_ CONST ART_LEAF* rep_leaf_opt,
    _Out_ USHORT* matched_out);

// ----------------- Local helpers -----------------
static VOID fill_seq(UCHAR* dst, USHORT len, UCHAR start) {
    for (USHORT i = 0; i < len; ++i) dst[i] = (UCHAR)(start + i);
}

static VOID test_free_node_base(ART_NODE* n)
{
    if (n) ExFreePool2(n, ART_TAG, NULL, 0);
}

static BOOLEAN n4_set(ART_NODE4* n4, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n4 || !keys || !ch || cnt > 4) return FALSE;
    RtlZeroMemory(n4->keys, sizeof(n4->keys));
    RtlZeroMemory(n4->children, sizeof(n4->children));
    for (USHORT i = 0; i < cnt; i++) {
        n4->keys[i] = keys[i];
        n4->children[i] = ch[i];
    }
    n4->base.num_of_child = cnt;
    return TRUE;
}
// Bazı testlerde rep leaf lazım
static ART_LEAF* test_alloc_leaf_with_key_bytes(const UCHAR* bytes, USHORT len) {
    SIZE_T total = sizeof(ART_LEAF) + len;
    ART_LEAF* lf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, ART_TAG);
    if (!lf) return NULL;
    RtlZeroMemory(lf, total);
    lf->key_length = len;
    if (len && bytes) RtlCopyMemory(lf->key, bytes, len);
    return lf;
}

static VOID test_free_leaf_any(ART_LEAF* lf) {
    if (!lf) return;
    ExFreePool2(lf, ART_TAG, NULL, 0);
}

// ----------------- Tests -----------------
BOOLEAN test_prefix_compare_param_validation()
{
    TEST_START("prefix_compare: param validation");
    reset_mock_state();

    UCHAR k[4] = { 1,2,3,4 };
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc base");
    n->prefix_length = 2; n->prefix[0] = 1; n->prefix[1] = 2;

    USHORT mo = 0xBEEF;

    // matched_out NULL -> FALSE
#pragma warning(push)
#pragma warning(disable:6387)
    TEST_ASSERT(prefix_compare(n, k, 4, 0, NULL, NULL) == FALSE, "matched_out==NULL -> FALSE");
#pragma warning(pop)

    // node NULL -> FALSE, matched_out sıfırlanır
    mo = 777;
#pragma warning(push)
#pragma warning(disable:6387)
    TEST_ASSERT(prefix_compare(NULL, k, 4, 0, NULL, &mo) == FALSE, "node==NULL -> FALSE");
#pragma warning(pop)
    TEST_ASSERT(mo == 0, "matched_out pre-zero");

    // key NULL -> FALSE
    mo = 123;
#pragma warning(push)
#pragma warning(disable:6387)
    TEST_ASSERT(prefix_compare(n, NULL, 4, 0, NULL, &mo) == FALSE, "key==NULL -> FALSE");
#pragma warning(pop)
    TEST_ASSERT(mo == 0, "matched_out pre-zero");

    // depth > key_length -> FALSE
    mo = 555;
    TEST_ASSERT(prefix_compare(n, k, 2, 3, NULL, &mo) == FALSE, "depth>key_length -> FALSE");
    TEST_ASSERT(mo == 0, "pre-zero stays");

    // remaining==0 (depth==key_length, prefix non-empty) -> FALSE
    mo = 999;
    TEST_ASSERT(prefix_compare(n, k, 2, 2, NULL, &mo) == FALSE, "remaining==0 -> FALSE");
    TEST_ASSERT(mo == 0, "pre-zero stays");

    test_free_node_base(n); // UNDEFINED
    TEST_END("prefix_compare: param validation");
    return TRUE;
}

// 2) Boş prefix trivial match
BOOLEAN test_prefix_compare_empty_prefix()
{
    TEST_START("prefix_compare: empty prefix");
    reset_mock_state();

    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = 0;

    UCHAR k[1] = { 0xAB };
    USHORT mo = 0xDEAD;

    TEST_ASSERT(prefix_compare(n, k, 1, 0, NULL, &mo) == TRUE, "empty prefix -> TRUE");
    TEST_ASSERT(mo == 0, "matched_out==0 for empty prefix");

    test_free_node_base(n);
    TEST_END("prefix_compare: empty prefix");
    return TRUE;
}

// 3) Stored-window: tam eşleşme ve mismatch
BOOLEAN test_prefix_compare_stored_window_basic()
{
    TEST_START("prefix_compare: stored-window basic");
    reset_mock_state();

    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = (USHORT)min((USHORT)4, (USHORT)MAX_PREFIX_LENGTH);
    fill_seq(n->prefix, n->prefix_length, 0x30); // 30 31 32 33

    UCHAR key[16] = { 0 };
    RtlCopyMemory(key, n->prefix, n->prefix_length); // match
    USHORT mo = 0xFFFF;

    // remaining >= prefix_lengthtam eşleşme
    TEST_ASSERT(prefix_compare(n, key, 16, 0, NULL, &mo) == TRUE, "full match within stored window");
    TEST_ASSERT(mo == n->prefix_length, "matched_out == prefix_length");

    // mismatch (ilk byte)
    mo = 0xAAAA;
    key[0] ^= 0x7F;
    TEST_ASSERT(prefix_compare(n, key, 16, 0, NULL, &mo) == FALSE, "mismatch in stored window");
    TEST_ASSERT(mo == 0, "first mismatch index");

    test_free_node_base(n);
    TEST_END("prefix_compare: stored-window basic");
    return TRUE;
}

// 4) Stored-window: mismatch ama rep_leaf key’i doğruluyortolerans
BOOLEAN test_prefix_compare_header_drift_with_rep_leaf()
{
    TEST_START("prefix_compare: header drift tolerated by rep_leaf");
    reset_mock_state();

    // Node: 6 byte prefix
    const USHORT P = (USHORT)min((USHORT)6, (USHORT)MAX_PREFIX_LENGTH);
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = P;
    fill_seq(n->prefix, P, 0x40); // 40..45

    // Key: n->prefix ile aynı ama index 2’de farklı (drift)
    UCHAR key[32] = { 0 };
    RtlCopyMemory(key, n->prefix, P);
    key[2] = 0x99; // header drift

    // Rep leaf: gerçek baytlar key ile uyumlu olmalı0..P-1 aynı olacak şekilde dolduralım
    UCHAR leaf_bytes[64] = { 0 };
    for (USHORT i = 0; i < P; i++) leaf_bytes[i] = key[i]; // leaf, key’i doğruluyor
    ART_LEAF* lf = test_alloc_leaf_with_key_bytes(leaf_bytes, (USHORT)(P + 4)); TEST_ASSERT(lf, "leaf alloc");

    USHORT mo = 0xEEEE;
    BOOLEAN ok = prefix_compare(n, key, (USHORT)RTL_NUMBER_OF(key), 0, lf, &mo);
    TEST_ASSERT(ok == TRUE, "rep_leaf ile drift tolere edilmeli (tam match)");
    TEST_ASSERT(mo == n->prefix_length, "matched_out == prefix_length");

    test_free_leaf_any(lf);
    test_free_node_base(n);
    TEST_END("prefix_compare: header drift tolerated by rep_leaf");
    return TRUE;
}

// 5) Extended path: key mantıksal prefix’ten KISAnot full, doğru matched_out
BOOLEAN test_prefix_compare_extended_key_shorter()
{
    TEST_START("prefix_compare: extended (key shorter)");
    reset_mock_state();

    // Mantıksal prefix uzun, stored MAX_PREFIX_LENGTH ile sınırlı
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = (USHORT)(MAX_PREFIX_LENGTH + 5);
    fill_seq(n->prefix, (USHORT)MAX_PREFIX_LENGTH, 0x50);

    // key_length: first_window + extra_key; extra_key < logical_extra
    const USHORT first_window = (USHORT)MAX_PREFIX_LENGTH;
    const USHORT extra_key = 4;
    const USHORT total_len = (USHORT)(first_window + extra_key);

    UCHAR key[512] = { 0 };
    for (USHORT i = 0; i < total_len; i++) key[i] = (UCHAR)(0x50 + i); // hepsi uyumlu

    // Rep leaf: extended kısmı doğrulayacak kadar byte içersin (>= total_len)
    ART_LEAF* lf = test_alloc_leaf_with_key_bytes(key, (USHORT)(total_len + 8)); TEST_ASSERT(lf, "leaf alloc");

    USHORT mo = 0x3333;
    BOOLEAN ok = prefix_compare(n, key, total_len, 0, lf, &mo);
    TEST_ASSERT(ok == FALSE, "key is shorter than logical prefix, not fully match");
    TEST_ASSERT(mo == total_len, "matched_out == key sonuna kadar");

    test_free_leaf_any(lf);
    test_free_node_base(n);
    TEST_END("prefix_compare: extended (key shorter)");
    return TRUE;
}

// 6) Extended path: key YETER ve rep leaf ile TAM eşleşmeTRUE
BOOLEAN test_prefix_compare_extended_full_match_with_rep_leaf()
{
    TEST_START("prefix_compare: extended full match with rep_leaf");
    reset_mock_state();

    // Mantıksal prefix uzun
    const USHORT LOGICAL = (USHORT)(MAX_PREFIX_LENGTH + 12);
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = LOGICAL;
    fill_seq(n->prefix, (USHORT)MAX_PREFIX_LENGTH, 0x60);

    // key: LOGICAL kadar uyumlu byte üretelim
    UCHAR key[1024] = { 0 };
    for (USHORT i = 0; i < LOGICAL; i++) {
        key[i] = (UCHAR)(0x60 + i);
    }

    ART_LEAF* lf = test_alloc_leaf_with_key_bytes(key, (USHORT)(LOGICAL + 10)); TEST_ASSERT(lf, "leaf alloc");

    USHORT mo = 0x1111;
    BOOLEAN ok = prefix_compare(n, key, (USHORT)(LOGICAL + 5), 0, lf, &mo);
    TEST_ASSERT(ok == TRUE, "extended full match (rep_leaf)TRUE");
    TEST_ASSERT(mo == LOGICAL, "matched_out == logical prefix length");

    test_free_leaf_any(lf);
    test_free_node_base(n);
    TEST_END("prefix_compare: extended full match with rep_leaf");
    return TRUE;
}

// 7) Extended path: leaf baytları YETMEZnot-full, doğru matched_out
BOOLEAN test_prefix_compare_extended_insufficient_leaf_bytes()
{
    TEST_START("prefix_compare: extended leaf insufficient");
    reset_mock_state();

    const USHORT LOGICAL = (USHORT)(MAX_PREFIX_LENGTH + 10);
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = LOGICAL;
    fill_seq(n->prefix, (USHORT)MAX_PREFIX_LENGTH, 0x70);

    // key LOGICAL kadar uyumlu
    UCHAR key[1024] = { 0 };
    for (USHORT i = 0; i < LOGICAL; i++) key[i] = (UCHAR)(0x70 + i);

    // rep leaf sadece first_window + 3 byte sağlayabilsin
    const USHORT first_window = (USHORT)MAX_PREFIX_LENGTH;
    const USHORT leaf_cover = (USHORT)(first_window + 3);
    ART_LEAF* lf = test_alloc_leaf_with_key_bytes(key, leaf_cover); TEST_ASSERT(lf, "leaf alloc");

    USHORT mo = 0x2222;
    BOOLEAN ok = prefix_compare(n, key, (USHORT)(LOGICAL + 2), 0, lf, &mo);
    TEST_ASSERT(ok == FALSE, "leaf bytes insufficientnot full");
    TEST_ASSERT(mo == (first_window + 3), "matched_out == covered bytes");

    test_free_leaf_any(lf);
    test_free_node_base(n);
    TEST_END("prefix_compare: extended leaf insufficient");
    return TRUE;
}

// 8) Lazy fetch (rep_leaf_opt==NULL): minimum(node) üzerinden başarı
BOOLEAN test_prefix_compare_lazy_minimum_fetch_success()
{
    TEST_START("prefix_compare: lazy minimum() fetch success");
    reset_mock_state();

    // Gerçek bir node yapısı kur: NODE4 + tek yaprak (minimum bu yaprağı dönebilmeli)
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "alloc node4");
    n4->base.type = NODE4;

    // Mantıksal prefix uzun (extended yoluna girsin)
    const USHORT LOGICAL = (USHORT)(MAX_PREFIX_LENGTH + 6);
    n4->base.prefix_length = LOGICAL;
    fill_seq(n4->base.prefix, (USHORT)MAX_PREFIX_LENGTH, 0x22);

    // Key üret
    UCHAR key[256] = { 0 };
    for (USHORT i = 0; i < LOGICAL; i++) key[i] = (UCHAR)(0x22 + i);

    // Leaf hazırla ve tek çocuk olarak bağla (minimum bu leaf’e ulaşabilsin)
    ART_LEAF* lf = make_leaf(key, LOGICAL, 0xDEAD); TEST_ASSERT(lf, "leaf alloc");
    ART_NODE* ch = (ART_NODE*)SET_LEAF(lf);
    UCHAR k0 = 0; // herhangi bir key
    TEST_ASSERT(n4_set(n4, &k0, 1, &ch), "wire child");

    USHORT mo = 0x9999;
    BOOLEAN ok = prefix_compare(&n4->base, key, (USHORT)(LOGICAL + 3), 0, /*rep_leaf_opt*/NULL, &mo);
    TEST_ASSERT(ok == TRUE, "lazy minimum fetch must allow full match");
    TEST_ASSERT(mo == LOGICAL, "matched_out == logical");

#ifdef TRACK_MINIMUM_CALLS
    extern ULONG g_minimum_call_count;
    TEST_ASSERT(g_minimum_call_count >= 1, "minimum() should be consulted at least once");
#endif

    // cleanup
    ART_LEAF* raw = LEAF_RAW(ch); free_leaf(&raw);
    ART_NODE* base = &n4->base; free_node(&base);

    TEST_END("prefix_compare: lazy minimum() fetch success");
    return TRUE;
}

// 9) Yan-etki: alloc/free yapılmamalı (minimum kullanmadığımız varyant)
BOOLEAN test_prefix_compare_no_allocfree_sideeffects()
{
    TEST_START("prefix_compare: no alloc/free side-effects");
    reset_mock_state();

    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = (USHORT)min((USHORT)6, (USHORT)MAX_PREFIX_LENGTH);
    fill_seq(n->prefix, n->prefix_length, 0x33);

    UCHAR key[64] = { 0 };
    for (USHORT i = 0; i < n->prefix_length; i++) key[i] = (UCHAR)(0x33 + i);

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    USHORT mo = 0;
    (void)prefix_compare(n, key, 64, 0, /*rep*/NULL, &mo); // bu çağrıda minimum devreye girebilir; güvenli yol: rep leaf verelim
    ART_LEAF* lf = test_alloc_leaf_with_key_bytes(key, (USHORT)(n->prefix_length + 8));
    (void)prefix_compare(n, key, 64, 0, lf, &mo);

    TEST_ASSERT(g_alloc_call_count - a0 <= 1, "SUT içinde tahsis beklenmez; rep leaf alloc test kurulumudur");
    TEST_ASSERT(g_free_call_count - f0 == 0, "SUT free yapmaz");

    test_free_leaf_any(lf);
    test_free_node_base(n);

    TEST_END("prefix_compare: no alloc/free side-effects");
    return TRUE;
}

// ----------------- Runner -----------------
NTSTATUS run_all_prefix_compare_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting prefix_compare Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_prefix_compare_param_validation())                  all = FALSE;
    if (!test_prefix_compare_empty_prefix())                      all = FALSE;
    if (!test_prefix_compare_stored_window_basic())               all = FALSE;
    if (!test_prefix_compare_header_drift_with_rep_leaf())        all = FALSE;
    if (!test_prefix_compare_extended_key_shorter())              all = FALSE;
    if (!test_prefix_compare_extended_full_match_with_rep_leaf()) all = FALSE;
    if (!test_prefix_compare_extended_insufficient_leaf_bytes())  all = FALSE;
    if (!test_prefix_compare_lazy_minimum_fetch_success())        all = FALSE;
    if (!test_prefix_compare_no_allocfree_sideeffects())          all = FALSE;

    LOG_MSG("\n========================================\n");
    if (all) LOG_MSG("ALL prefix_compare TESTS PASSED!\n");
    else     LOG_MSG("SOME prefix_compare TESTS FAILED!\n");
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif