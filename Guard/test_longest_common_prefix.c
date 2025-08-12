#include "test_art.h"

// Function under test
STATIC USHORT longest_common_prefix(CONST ART_LEAF* leaf1, CONST ART_LEAF* leaf2, USHORT depth);

// ---------- tiny helpers (no CRT) ----------
static ART_LEAF* t_alloc_leaf_with_bytes(USHORT len, UCHAR base)
{
    SIZE_T sz = sizeof(ART_LEAF) + len;
    ART_LEAF* lf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, ART_TAG);
    if (!lf) return NULL;
    RtlZeroMemory(lf, sz);
    lf->value = 0x12345678;
    lf->key_length = len;
    for (USHORT i = 0; i < len; ++i) lf->key[i] = (UCHAR)(base + (UCHAR)i);
    return lf;
}

static ART_LEAF* t_alloc_leaf_from_buf(CONST UCHAR* src, USHORT len)
{
    SIZE_T sz = sizeof(ART_LEAF) + len;
    ART_LEAF* lf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, ART_TAG);
    if (!lf) return NULL;
    RtlZeroMemory(lf, sz);
    lf->value = 0x87654321;
    lf->key_length = len;
    if (len && src) RtlCopyMemory(lf->key, src, len);
    return lf;
}

static VOID t_free_leaf(ART_LEAF* lf) {
    if (lf) {
        ExFreePool2(lf, ART_TAG, NULL, 0);
    }
}


/* =========================================================
   Test 1: Guard checks (NULL and depth constraints)
   Covers:
     (1.1) leaf1==NULL
     (1.2) leaf2==NULL
     (1.3) depth > leaf1->key_length
     (1.4) depth > leaf2->key_length
     (1.5) depth == leaf1->key_length
     (1.6) depth == leaf2->key_length
   Also verifies: no alloc/free inside the function.
   ========================================================= */
BOOLEAN test_lcp_guards()
{
    TEST_START("longest_common_prefix: guard checks");

    reset_mock_state();

    // Reusable leaves (non-NULL)
    ART_LEAF* a = t_alloc_leaf_with_bytes(5, 0x10);
    ART_LEAF* b = t_alloc_leaf_with_bytes(5, 0x20);
    TEST_ASSERT(a && b, "1-pre: allocate non-NULL leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    // (1.1) leaf1==NULL
    USHORT r = longest_common_prefix(NULL, b, 0);
    TEST_ASSERT(r == 0, "1.1: NULL leaf1 must return 0");

    // (1.2) leaf2==NULL
    r = longest_common_prefix(a, NULL, 0);
    TEST_ASSERT(r == 0, "1.2: NULL leaf2 must return 0");

    // (1.3) depth > leaf1->key_length
    r = longest_common_prefix(a, b, 6); // a->key_length==5
    TEST_ASSERT(r == 0, "1.3: depth > leaf1 length must return 0");

    // (1.4) depth > leaf2->key_length
    r = longest_common_prefix(a, b, 6);
    TEST_ASSERT(r == 0, "1.4: depth > leaf2 length must return 0");

    // (1.5) depth == leaf1->key_length
    r = longest_common_prefix(a, b, 5);
    TEST_ASSERT(r == 0, "1.5: depth == leaf1 length must return 0");

    // (1.6) depth == leaf2->key_length
    r = longest_common_prefix(b, a, 5);
    TEST_ASSERT(r == 0, "1.6: depth == leaf2 length must return 0");

    // No internal alloc/free expected
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no alloc/free inside LCP");

    t_free_leaf(a);
    t_free_leaf(b);

    TEST_END("longest_common_prefix: guard checks");
    return TRUE;
}


/* =========================================================
   Test 2: Full suffix match (identical tails)
   Case:
     - leaf1 and leaf2 have identical bytes from depth onward.
     Expect:
       return = min(l1_len - depth, l2_len - depth)
   ========================================================= */
BOOLEAN test_lcp_full_match()
{
    TEST_START("longest_common_prefix: full suffix match");

    reset_mock_state();

    // Keys:  [A B C D E], [X B C D E]  with depth=1 -> identical from index 1: "BCDE"
    UCHAR k1[] = { 'A','B','C','D','E' };
    UCHAR k2[] = { 'X','B','C','D','E' };
    ART_LEAF* l1 = t_alloc_leaf_from_buf(k1, (USHORT)RTL_NUMBER_OF(k1));
    ART_LEAF* l2 = t_alloc_leaf_from_buf(k2, (USHORT)RTL_NUMBER_OF(k2));
    TEST_ASSERT(l1 && l2, "2-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    USHORT r = longest_common_prefix(l1, l2, 1);
    TEST_ASSERT(r == 4, "2.1: LCP from depth=1 should be 4 (BCDE)");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "2.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: full suffix match");
    return TRUE;
}


/* =========================================================
   Test 3: Early mismatch right after depth
   Case:
     - Bytes at position 'depth' differ.
     Expect:
       return = 0
   ========================================================= */
BOOLEAN test_lcp_early_mismatch()
{
    TEST_START("longest_common_prefix: early mismatch");

    reset_mock_state();

    // Keys: [A B C], [A X C], depth=1 -> compare from index 1: B vs X -> mismatch at +0 -> 0
    UCHAR k1[] = { 'A','B','C' };
    UCHAR k2[] = { 'A','X','C' };
    ART_LEAF* l1 = t_alloc_leaf_from_buf(k1, (USHORT)RTL_NUMBER_OF(k1));
    ART_LEAF* l2 = t_alloc_leaf_from_buf(k2, (USHORT)RTL_NUMBER_OF(k2));
    TEST_ASSERT(l1 && l2, "3-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    USHORT r = longest_common_prefix(l1, l2, 1);
    TEST_ASSERT(r == 0, "3.1: immediate mismatch returns 0");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "3.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: early mismatch");
    return TRUE;
}


/* =========================================================
   Test 4: Late mismatch (after some equal bytes)
   Case:
     - A few bytes match after depth, then mismatch.
     Expect:
       return = index of first mismatch
   ========================================================= */
BOOLEAN test_lcp_late_mismatch()
{
    TEST_START("longest_common_prefix: late mismatch");

    reset_mock_state();

    // Keys: [Q R S T U], [Q R s T U], depth=1 -> compare "R S T U" vs "R s T U"
    // At offset +1 from depth (i.e., absolute index 2): 'S' vs 's' differ -> return 1
    UCHAR k1[] = { 'Q','R','S','T','U' };
    UCHAR k2[] = { 'Q','R','s','T','U' };
    ART_LEAF* l1 = t_alloc_leaf_from_buf(k1, (USHORT)RTL_NUMBER_OF(k1));
    ART_LEAF* l2 = t_alloc_leaf_from_buf(k2, (USHORT)RTL_NUMBER_OF(k2));
    TEST_ASSERT(l1 && l2, "4-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    USHORT r = longest_common_prefix(l1, l2, 1);
    TEST_ASSERT(r == 1, "4.1: one byte matches after depth then mismatch , return 1");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "4.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: late mismatch");
    return TRUE;
}


/* =========================================================
   Test 5: Asymmetric remaining lengths, full match
   Case:
     - From depth onward, shorter remainder fully matches a prefix of the longer remainder.
     Expect:
       return = min(remaining1, remaining2)  (i.e., remaining of the shorter)
   ========================================================= */
BOOLEAN test_lcp_asymmetric_lengths_full_match()
{
    TEST_START("longest_common_prefix: asymmetric lengths full match");

    reset_mock_state();

    // l1: [A B C D], l2: [A B C D E F], depth=0 -> full l1 matches start of l2
    UCHAR k1[] = { 'A','B','C','D' };
    UCHAR k2[] = { 'A','B','C','D','E','F' };
    ART_LEAF* l1 = t_alloc_leaf_from_buf(k1, (USHORT)RTL_NUMBER_OF(k1));
    ART_LEAF* l2 = t_alloc_leaf_from_buf(k2, (USHORT)RTL_NUMBER_OF(k2));
    TEST_ASSERT(l1 && l2, "5-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    USHORT r = longest_common_prefix(l1, l2, 0);
    TEST_ASSERT(r == 4, "5.1: shorter remainder length (4) returned on full match");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "5.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: asymmetric lengths full match");
    return TRUE;
}


/* =========================================================
   Test 6: Depth in the middle, partial match length computed correctly
   Case:
     - Non-zero depth; some equal bytes, then end due to shorter leaf.
   ========================================================= */
BOOLEAN test_lcp_middle_depth_end_by_shorter()
{
    TEST_START("longest_common_prefix: middle depth, end by shorter");

    reset_mock_state();

    // l1: [0 1 2 3 4], l2: [0 1 2], depth=1
    // Compare from index 1: l1 => [1 2 3 4], l2 => [1 2]
    // Full match over l2's remainder -> return 2
    ART_LEAF* l1 = t_alloc_leaf_with_bytes(5, 0x00);
    ART_LEAF* l2 = t_alloc_leaf_with_bytes(3, 0x00);
    TEST_ASSERT(l1 && l2, "6-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    USHORT r = longest_common_prefix(l1, l2, 1);
    TEST_ASSERT(r == 2, "6.1: should return remaining length of shorter (2)");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "6.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: middle depth, end by shorter");
    return TRUE;
}


/* =========================================================
   Test 7: Zero-length keys with depth 0
   Case:
     - Both leaves key_length==0, depth==0 , guard path(depth==len) returns 0
   ========================================================= */
BOOLEAN test_lcp_zero_length_keys()
{
    TEST_START("longest_common_prefix: zero-length keys");

    reset_mock_state();

    ART_LEAF* l1 = t_alloc_leaf_with_bytes(0, 0x00);
    ART_LEAF* l2 = t_alloc_leaf_with_bytes(0, 0x00);
    TEST_ASSERT(l1 && l2, "7-pre: allocate zero-length leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    USHORT r = longest_common_prefix(l1, l2, 0);
    TEST_ASSERT(r == 0, "7.1: depth==key_length (0) must return 0");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "7.1: no alloc/free inside LCP");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: zero-length keys");
    return TRUE;
}


/* =========================================================
   Test 8: No alloc/free side-effects (sanity)
   Purpose:
     - Ensure LCP never allocates/frees internally.
   ========================================================= */
BOOLEAN test_lcp_no_allocfree_sideeffects()
{
    TEST_START("longest_common_prefix: no alloc/free side-effects");

    reset_mock_state();

    ART_LEAF* l1 = t_alloc_leaf_with_bytes(4, 0x10);
    ART_LEAF* l2 = t_alloc_leaf_with_bytes(4, 0x10);
    TEST_ASSERT(l1 && l2, "8-pre: allocate leaves");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    (void)longest_common_prefix(l1, l2, 0);
    (void)longest_common_prefix(l1, l2, 1);
    (void)longest_common_prefix(l1, l2, 2);

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.1: counters unchanged across calls");

    t_free_leaf(l1);
    t_free_leaf(l2);

    TEST_END("longest_common_prefix: no alloc/free side-effects");
    return TRUE;
}


/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_longest_common_prefix_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting longest_common_prefix() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_lcp_guards())                        all_passed = FALSE; // 1
    if (!test_lcp_full_match())                    all_passed = FALSE; // 2
    if (!test_lcp_early_mismatch())                all_passed = FALSE; // 3
    if (!test_lcp_late_mismatch())                 all_passed = FALSE; // 4
    if (!test_lcp_asymmetric_lengths_full_match()) all_passed = FALSE; // 5
    if (!test_lcp_middle_depth_end_by_shorter())   all_passed = FALSE; // 6
    if (!test_lcp_zero_length_keys())              all_passed = FALSE; // 7
    if (!test_lcp_no_allocfree_sideeffects())      all_passed = FALSE; // 8

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL longest_common_prefix() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME longest_common_prefix() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
