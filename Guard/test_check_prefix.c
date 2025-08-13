#include "test_art.h"

// Function under test
STATIC USHORT check_prefix(_In_ CONST ART_NODE* node,
    _In_reads_bytes_(key_length) CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ USHORT depth);

// ---------- small helpers ----------
static VOID test_free_node_base(ART_NODE* n)
{
    if (n) ExFreePool2(n, ART_TAG, NULL, 0);
}

static VOID test_fill_prefix(UCHAR* dst, USHORT len, UCHAR start)
{
    for (USHORT i = 0; i < len; ++i) dst[i] = (UCHAR)(start + (UCHAR)i);
}

/* =========================================================
   Test 1: Parameter validation and early exits
   ========================================================= */
BOOLEAN test_check_prefix_param_validation()
{
    TEST_START("check_prefix: parameter validation");

    // (1.1) node==NULL
    reset_mock_state();
    {
        UCHAR k[8] = { 0 };
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable: 6387)
        USHORT r = check_prefix(NULL, k, 8, 0);
#pragma warning(pop)
        TEST_ASSERT(r == 0, "1.1: node==NULL must return 0");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.1: No alloc/free");
    }

    // (1.2) key==NULL
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n != NULL, "1.2-pre: node alloc");
        n->prefix_length = 3; test_fill_prefix(n->prefix, (USHORT)min(3, (USHORT)MAX_PREFIX_LENGTH), 0x10);
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable: 6387)
        USHORT r = check_prefix(n, NULL, 3, 0);
#pragma warning(pop)
        TEST_ASSERT(r == 0, "1.2: key==NULL must return 0");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.2: No alloc/free");
        test_free_node_base(n);
    }

    // (1.3) depth >= key_length
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "1.3-pre: node alloc");
        n->prefix_length = 2; test_fill_prefix(n->prefix, 2, 0x20);
        UCHAR k[4] = { 0x20,0x21,0x22,0x23 };
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        USHORT r = check_prefix(n, k, 3, 3); // depth == key_length
        TEST_ASSERT(r == 0, "1.3: depth>=key_length must return 0");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.3: No alloc/free");
        test_free_node_base(n);
    }

    // (1.4) key_length > MAX_KEY_LENGTH
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "1.4-pre: node alloc");
        n->prefix_length = 1; n->prefix[0] = 0x33;
#pragma warning(push)
#pragma warning(disable: 4189)
        UCHAR dummy = 0x33;
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(pop)
#if (MAX_KEY_LENGTH < MAXUSHORT)
        const USHORT too_long = (USHORT)(MAX_KEY_LENGTH + 1);
        USHORT r = check_prefix(n, &dummy, too_long, 0);
        TEST_ASSERT(r == 0, "1.4: key_length > MAX_KEY_LENGTH must return 0");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.4: No alloc/free");
#else
        LOG_MSG("[INFO] 1.4 skipped: USHORT cannot represent MAX_KEY_LENGTH+1 (MAX_KEY_LENGTH==MAXUSHORT)\n");
#endif
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 1: parameter/limit guards verified\n");
    TEST_END("check_prefix: parameter validation");
    return TRUE;
}

/* =========================================================
   Test 2: Zero prefix
   (Former depth-limit check removed: MAX_TREE_DEPTH no longer exists.)
   ========================================================= */
BOOLEAN test_check_prefix_zero_prefix()
{
    TEST_START("check_prefix: zero prefix_length");

    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "2-pre: node alloc");
        n->prefix_length = 0;
        UCHAR k[2] = { 0xAA,0xBB };
        USHORT r = check_prefix(n, k, 2, 0);
        TEST_ASSERT(r == 0, "2: zero prefix_length returns 0");
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 2: zero-prefix branch verified\n");
    TEST_END("check_prefix: zero prefix_length");
    return TRUE;
}

/* =========================================================
   Test 3: Full matches (no truncation by key)
   ========================================================= */
BOOLEAN test_check_prefix_full_match()
{
    TEST_START("check_prefix: full-match cases");

    // (3.1)
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.1-pre: node alloc");
        n->prefix_length = 4;
        test_fill_prefix(n->prefix, 4, 0x30); // 30 31 32 33

        UCHAR k[10] = { 0 };
        for (int i = 0; i < 10; i++) k[i] = (UCHAR)(0x20 + i);
        k[0] = 0x30; k[1] = 0x31; k[2] = 0x32; k[3] = 0x33;

        const USHORT depth = 0;
        const USHORT remaining = (USHORT)(10 - depth);
        const USHORT expected = (USHORT)((4 < (USHORT)MAX_PREFIX_LENGTH ? 4 : (USHORT)MAX_PREFIX_LENGTH) < remaining
            ? (4 < (USHORT)MAX_PREFIX_LENGTH ? 4 : (USHORT)MAX_PREFIX_LENGTH)
            : remaining);

        USHORT r = check_prefix(n, k, 10, depth);
        TEST_ASSERT(r == expected, "3.1: full prefix length");
        test_free_node_base(n);
    }

    // (3.2)
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.2-pre: node alloc");
        n->prefix_length = 5;
        test_fill_prefix(n->prefix, 5, 0x40); // 40..44

        UCHAR k[12] = { 0 };
        USHORT depth = 3; // remaining = 9
        for (int i = 0; i < 5; i++) k[depth + i] = (UCHAR)(0x40 + i);

        const USHORT remaining = (USHORT)(12 - depth);
        const USHORT pfx_cap = (USHORT)((n->prefix_length < (USHORT)MAX_PREFIX_LENGTH)
            ? n->prefix_length : (USHORT)MAX_PREFIX_LENGTH);
        const USHORT expected = (pfx_cap < remaining) ? pfx_cap : remaining;

        USHORT r = check_prefix(n, k, 12, depth);
        TEST_ASSERT(r == expected, "3.2: min(prefix, MAX_PREFIX_LENGTH, remaining)");
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 3: full-match returns expected lengths\n");
    TEST_END("check_prefix: full-match cases");
    return TRUE;
}

/* =========================================================
   Test 4: Truncation by MAX_PREFIX_LENGTH and by remaining key
   ========================================================= */
BOOLEAN test_check_prefix_truncation_paths()
{
    TEST_START("check_prefix: truncation paths");

    // (4.1) truncation to MAX_PREFIX_LENGTH
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "4.1-pre: node alloc");
        n->prefix_length = (USHORT)(MAX_PREFIX_LENGTH + 10);
        test_fill_prefix(n->prefix, MAX_PREFIX_LENGTH, 0x50);
        UCHAR k[512] = { 0 };
        for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) k[i] = (UCHAR)(0x50 + i);

        USHORT r = check_prefix(n, k, (USHORT)RTL_NUMBER_OF(k), 0);
        TEST_ASSERT(r == MAX_PREFIX_LENGTH, "4.1: return MAX_PREFIX_LENGTH on truncation");
        test_free_node_base(n);
    }

    // (4.2) remaining shorter than prefix
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "4.2-pre: node alloc");
        n->prefix_length = 12;
        test_fill_prefix(n->prefix, 12, 0x60);

        UCHAR k[20] = { 0 };
        const USHORT depth = 15; // remaining = 5
        const USHORT remaining = (USHORT)(20 - depth);
        for (USHORT i = 0; i < remaining; i++) k[depth + i] = (UCHAR)(0x60 + i);

        const USHORT pfx_cap = (USHORT)((n->prefix_length < (USHORT)MAX_PREFIX_LENGTH) ? n->prefix_length : (USHORT)MAX_PREFIX_LENGTH);
        const USHORT expected = (pfx_cap < remaining) ? pfx_cap : remaining;

        USHORT r = check_prefix(n, k, 20, depth);
        TEST_ASSERT(r == expected, "4.2: min(prefix, MAX_PREFIX_LENGTH, remaining)");
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 4: truncation cases validated\n");
    TEST_END("check_prefix: truncation paths");
    return TRUE;
}

/* =========================================================
   Test 5: Mismatch detection (first, middle, last compared byte)
   ========================================================= */
BOOLEAN test_check_prefix_mismatch_positions()
{
    TEST_START("check_prefix: mismatch detection");

    UCHAR baseStart = 0x70;

    // (5.1) first byte mismatch
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.1-pre: node alloc");
        n->prefix_length = 6; test_fill_prefix(n->prefix, 6, baseStart);
        UCHAR k[16] = { 0 };
        for (int i = 0; i < 6; i++) k[i] = (UCHAR)(baseStart + i);
        k[0] = (UCHAR)(baseStart + 9);

        USHORT r = check_prefix(n, k, 16, 0);
        TEST_ASSERT(r == 0, "5.1: first byte mismatch -> 0");
        test_free_node_base(n);
    }

    // (5.2) middle mismatch at index 2
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.2-pre: node alloc");
        n->prefix_length = 6; test_fill_prefix(n->prefix, 6, baseStart);
        UCHAR k[16] = { 0 };
        for (int i = 0; i < 6; i++) k[i] = (UCHAR)(baseStart + i);
        k[2] = (UCHAR)(baseStart + 0x33);

        USHORT r = check_prefix(n, k, 16, 0);
        TEST_ASSERT(r == 2, "5.2: first mismatch at index 2");
        test_free_node_base(n);
    }

    // (5.3) mismatch at last compared index
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.3-pre: node alloc");
        n->prefix_length = 10;
        baseStart = 0x70;
        test_fill_prefix(n->prefix, 10, baseStart);

        UCHAR k[10] = { 0 };
        const USHORT depth = 3; // remaining = 7
        const USHORT key_len = 10;
        const USHORT remaining = (USHORT)(key_len - depth);

        const USHORT pfx_cap = (USHORT)((n->prefix_length < (USHORT)MAX_PREFIX_LENGTH) ? n->prefix_length : (USHORT)MAX_PREFIX_LENGTH);
        const USHORT cmp_len = (pfx_cap < remaining) ? pfx_cap : remaining;

        for (USHORT i = 0; i < cmp_len; i++) k[depth + i] = (UCHAR)(baseStart + i);
        if (cmp_len > 0) {
            k[depth + (cmp_len - 1)] = (UCHAR)(baseStart + 0x44);
        }

        USHORT r = check_prefix(n, k, key_len, depth);
        TEST_ASSERT(r == (cmp_len > 0 ? (cmp_len - 1) : 0), "5.3: last index mismatch");
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 5: mismatch position handling validated\n");
    TEST_END("check_prefix: mismatch detection");
    return TRUE;
}

/* =========================================================
   Test 6: Depth edge cases (unchanged)
   ========================================================= */
BOOLEAN test_check_prefix_depth_edges()
{
    TEST_START("check_prefix: depth edge cases");

    // (6.1) remaining_key_length == 1 and it matches
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "6.1-pre: node alloc");
        n->prefix_length = 4; test_fill_prefix(n->prefix, 4, 0x90);
        UCHAR k[6] = { 0 };
        k[5 - 1] = 0x90;  // place one matching byte at the very end
        USHORT r = check_prefix(n, k, 5, 4); // depth = key_length-1
        TEST_ASSERT(r == 1, "6.1: single remaining matching byte returns 1");
        test_free_node_base(n);
    }

    // (6.2) depth == key_length , early return 0
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "6.2-pre: node alloc");
        n->prefix_length = 1; n->prefix[0] = 0xAB;
        UCHAR k2[4] = { 0xAB,0,0,0 };
        USHORT r = check_prefix(n, k2, 3, 3);
        TEST_ASSERT(r == 0, "6.2: depth==key_length must return 0");
        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 6: depth edges validated\n");
    TEST_END("check_prefix: depth edge cases");
    return TRUE;
}

/* =========================================================
   Test 7: No alloc/free side-effects (remove old MAX_TREE_DEPTH call)
   ========================================================= */
BOOLEAN test_check_prefix_no_allocfree_sideeffects()
{
    TEST_START("check_prefix: no alloc/free side-effects");

    reset_mock_state();
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "7-pre: node alloc");
    n->prefix_length = (USHORT)min(6, (int)MAX_PREFIX_LENGTH);
    test_fill_prefix(n->prefix, n->prefix_length, 0xA0);

    UCHAR k[32] = { 0 };
    for (int i = 0; i < n->prefix_length; i++) k[i] = (UCHAR)(0xA0 + i);

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    (void)check_prefix(n, k, 32, 0);
    (void)check_prefix(n, k, 32, 1);
    (void)check_prefix(n, k, 32, (USHORT)(n->prefix_length));
    // Removed: (USHORT)(MAX_TREE_DEPTH + 1)

    TEST_ASSERT(g_alloc_call_count == a0, "7: No allocations inside check_prefix");
    TEST_ASSERT(g_free_call_count == f0, "7: No frees inside check_prefix");

    test_free_node_base(n);

    LOG_MSG("[INFO] Test 7: side-effects counters unchanged as expected\n");
    TEST_END("check_prefix: no alloc/free side-effects");
    return TRUE;
}

/* =========================================================
   Extra Test: Truncation with mismatch before MAX_PREFIX_LENGTH
   ========================================================= */
BOOLEAN test_check_prefix_truncation_with_early_mismatch()
{
    TEST_START("check_prefix: truncation + early mismatch");

    reset_mock_state();
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = (USHORT)(MAX_PREFIX_LENGTH + 5);

    test_fill_prefix(n->prefix, MAX_PREFIX_LENGTH, 0x50);

    UCHAR k[512] = { 0 };
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) {
        k[i] = (UCHAR)(0x50 + i);
    }
    k[2] = (UCHAR)(0x99); // mismatch at index 2

    USHORT r = check_prefix(n, k, (USHORT)RTL_NUMBER_OF(k), 0);
    TEST_ASSERT(r == 2, "Must stop at early mismatch index");

    test_free_node_base(n);
    TEST_END("check_prefix: truncation + early mismatch");
    return TRUE;
}

/* =========================================================
   Extra Test: key_length == MAX_KEY_LENGTH
   ========================================================= */
BOOLEAN test_check_prefix_key_length_equals_max()
{
    TEST_START("check_prefix: key_length == MAX_KEY_LENGTH");

    reset_mock_state();
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");

    n->prefix_length = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, (USHORT)MAX_KEY_LENGTH);
    test_fill_prefix(n->prefix, n->prefix_length, 0x20);

    UCHAR k[MAX_KEY_LENGTH] = { 0 };
    for (USHORT i = 0; i < n->prefix_length; ++i) {
        k[i] = (UCHAR)(0x20 + i);
    }

    USHORT r = check_prefix(n, k, MAX_KEY_LENGTH, 0);
    TEST_ASSERT(r == n->prefix_length, "Must accept when key_length == MAX_KEY_LENGTH");

    test_free_node_base(n);
    TEST_END("check_prefix: key_length == MAX_KEY_LENGTH");
    return TRUE;
}

#if (MAX_PREFIX_LENGTH == 0)
BOOLEAN test_check_prefix_max_prefix_zero()
{
    TEST_START("check_prefix: MAX_PREFIX_LENGTH == 0");
    ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "alloc");
    n->prefix_length = 10; // window becomes 0 in SUT
    UCHAR k[8] = { 0 };
    USHORT r = check_prefix(n, k, 8, 0);
    TEST_ASSERT(r == 0, "window 0 -> result 0");
    test_free_node_base(n);
    TEST_END("check_prefix: MAX_PREFIX_LENGTH == 0");
    return TRUE;
}
#endif

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_check_prefix_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting check_prefix Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_check_prefix_param_validation())        all_passed = FALSE;
    if (!test_check_prefix_zero_prefix())             all_passed = FALSE; // updated
    if (!test_check_prefix_full_match())              all_passed = FALSE;
    if (!test_check_prefix_truncation_paths())        all_passed = FALSE;
    if (!test_check_prefix_mismatch_positions())      all_passed = FALSE;
    if (!test_check_prefix_depth_edges())             all_passed = FALSE;
    if (!test_check_prefix_no_allocfree_sideeffects())all_passed = FALSE;
    if (!test_check_prefix_truncation_with_early_mismatch()) all_passed = FALSE;
    if (!test_check_prefix_key_length_equals_max())          all_passed = FALSE;

#if (MAX_PREFIX_LENGTH == 0)
    if (!test_check_prefix_max_prefix_zero())         all_passed = FALSE;
#endif

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL check_prefix TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME check_prefix TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
