#include "test_art.h"

// Function under test
STATIC USHORT check_prefix(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth);
// ---------- small helpers (reuse pattern from other suites) ----------

static VOID test_free_node_base(ART_NODE* n)
{
    if (n) ExFreePoolWithTag(n, ART_TAG);
}

static VOID test_fill_prefix(UCHAR* dst, USHORT len, UCHAR start)
{
    for (USHORT i = 0; i < len; ++i) dst[i] = (UCHAR)(start + (UCHAR)i);
}

/* =========================================================
   Test 1: Parameter validation and early exits
   Purpose:
     - (1.1) node==NULL , 0
     - (1.2) key==NULL  , 0
     - (1.3) depth >= key_length , 0
     - (1.4) key_length > MAX_KEY_LENGTH , 0
     - No alloc/free inside check_prefix
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
        UCHAR dummy = 0x33;
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        USHORT too_long = (USHORT)((MAX_KEY_LENGTH < USHRT_MAX) ? (MAX_KEY_LENGTH + 1) : USHRT_MAX);
        USHORT r = check_prefix(n, &dummy, too_long, 0);
        TEST_ASSERT(r == 0, "1.4: key_length > MAX_KEY_LENGTH must return 0");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.4: No alloc/free");
        test_free_node_base(n);
    }

    DbgPrint("[INFO] Test 1: parameter/limit guards verified\n");
    TEST_END("check_prefix: parameter validation");
    return TRUE;
}

/* =========================================================
   Test 2: Excessive depth and zero prefix
   Purpose:
     - (2.1) depth > MAX_TREE_DEPTH , 0
     - (2.2) node->prefix_length == 0 , 0
   ========================================================= */
BOOLEAN test_check_prefix_depth_and_zero_prefix()
{
    TEST_START("check_prefix: excessive depth & zero prefix");

    // (2.1) depth > MAX_TREE_DEPTH
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "2.1-pre: node alloc");
        n->prefix_length = 2; test_fill_prefix(n->prefix, 2, 0x11);
        UCHAR k[4] = { 0x11,0x12,0x13,0x14 };
        USHORT r = check_prefix(n, k, 4, (USHORT)(MAX_TREE_DEPTH + 1));
        TEST_ASSERT(r == 0, "2.1: excessive depth must return 0");
        test_free_node_base(n);
    }

    // (2.2) zero prefix_length
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "2.2-pre: node alloc");
        n->prefix_length = 0;
        UCHAR k[2] = { 0xAA,0xBB };
        USHORT r = check_prefix(n, k, 2, 0);
        TEST_ASSERT(r == 0, "2.2: zero prefix_length returns 0");
        test_free_node_base(n);
    }

    DbgPrint("[INFO] Test 2: depth and zero-prefix branches verified\n");
    TEST_END("check_prefix: excessive depth & zero prefix");
    return TRUE;
}

/* =========================================================
   Test 3: Full matches (no truncation by key)
   Purpose:
     - Returns min(safe_prefix_length, remaining_key_length) when all bytes match
   Sub-checks:
     (3.1) depth=0, prefix_length=4, key has same 4 , return 4
     (3.2) depth>0, remaining >= prefix_length , return prefix_length
   ========================================================= */
BOOLEAN test_check_prefix_full_match()
{
    TEST_START("check_prefix: full-match cases");

    // (3.1)
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.1-pre: node alloc");
        n->prefix_length = 4; test_fill_prefix(n->prefix, 4, 0x30); // 30 31 32 33
        UCHAR k[10] = { 0 };
        for (int i = 0; i < 10; i++) k[i] = (UCHAR)(0x20 + i);
        // Overwrite first 4 with the node’s prefix to ensure match
        k[0] = 0x30; k[1] = 0x31; k[2] = 0x32; k[3] = 0x33;

        USHORT r = check_prefix(n, k, 10, 0);
        TEST_ASSERT(r == 4, "3.1: should return full prefix length 4");
        test_free_node_base(n);
    }

    // (3.2) depth shift
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.2-pre: node alloc");
        n->prefix_length = 5; test_fill_prefix(n->prefix, 5, 0x40); // 40..44
        UCHAR k[12] = { 0 };
        // Put the same sequence starting at offset depth=3
        USHORT depth = 3;
        for (int i = 0; i < 5; i++) k[depth + i] = (UCHAR)(0x40 + i);

        USHORT r = check_prefix(n, k, 12, depth);
        TEST_ASSERT(r == 5, "3.2: should return prefix length 5");
        test_free_node_base(n);
    }

    DbgPrint("[INFO] Test 3: full-match returns expected lengths\n");
    TEST_END("check_prefix: full-match cases");
    return TRUE;
}

/* =========================================================
   Test 4: Truncation by MAX_PREFIX_LENGTH and by remaining key
   Purpose:
     - (4.1) node->prefix_length > MAX_PREFIX_LENGTH , compares only MAX_PREFIX_LENGTH
     - (4.2) remaining_key_length shorter than prefix , return remaining length
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
        // Key large; make all compared bytes match
        UCHAR k[512] = { 0 };
        for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) k[i] = (UCHAR)(0x50 + i);

        USHORT r = check_prefix(n, k, (USHORT)RTL_NUMBER_OF(k), 0);
        TEST_ASSERT(r == MAX_PREFIX_LENGTH, "4.1: must return MAX_PREFIX_LENGTH on truncation");
        test_free_node_base(n);
    }

    // (4.2) remaining shorter than prefix
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "4.2-pre: node alloc");
        n->prefix_length = 12; test_fill_prefix(n->prefix, 12, 0x60);
        UCHAR k[20] = { 0 };
        USHORT depth = 15; // remaining = 20 - 15 = 5
        for (int i = 0; i < 5; i++) k[depth + i] = (UCHAR)(0x60 + i);

        USHORT r = check_prefix(n, k, 20, depth);
        TEST_ASSERT(r == 5, "4.2: must return remaining_key_length when smaller than prefix");
        test_free_node_base(n);
    }

    DbgPrint("[INFO] Test 4: truncation cases validated\n");
    TEST_END("check_prefix: truncation paths");
    return TRUE;
}

/* =========================================================
   Test 5: Mismatch detection (first, middle, last compared byte)
   Purpose:
     - Return the index of first mismatch within maximum_compare_length
   Sub-checks:
     (5.1) mismatch at first byte , return 0
     (5.2) mismatch in the middle , return mid index
     (5.3) mismatch at last byte of compare window , return last index
   ========================================================= */
BOOLEAN test_check_prefix_mismatch_positions()
{
    TEST_START("check_prefix: mismatch detection");

    // Base setup: prefix_length 6 , bytes 70..75
    UCHAR baseStart = 0x70;

    // (5.1) first byte mismatch
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.1-pre: node alloc");
        n->prefix_length = 6; test_fill_prefix(n->prefix, 6, baseStart);
        UCHAR k[16] = { 0 };
        // Make all intended matches, except the very first
        for (int i = 0; i < 6; i++) k[i] = (UCHAR)(baseStart + i);
        k[0] = (UCHAR)(baseStart + 9); // force mismatch at index 0

        USHORT r = check_prefix(n, k, 16, 0);
        TEST_ASSERT(r == 0, "5.1: first byte mismatch should return 0");
        test_free_node_base(n);
    }

    // (5.2) middle mismatch at index 2
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.2-pre: node alloc");
        n->prefix_length = 6; test_fill_prefix(n->prefix, 6, baseStart);
        UCHAR k[16] = { 0 };
        for (int i = 0; i < 6; i++) k[i] = (UCHAR)(baseStart + i);
        k[2] = (UCHAR)(baseStart + 0x33); // mismatch at index 2

        USHORT r = check_prefix(n, k, 16, 0);
        TEST_ASSERT(r == 2, "5.2: first mismatch at index 2");
        test_free_node_base(n);
    }

    // (5.3) mismatch at last compared index
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "5.3-pre: node alloc");
        // choose max_len=5 by limiting remaining length
        n->prefix_length = 10; test_fill_prefix(n->prefix, 10, baseStart);
        UCHAR k[10] = { 0 };
        USHORT depth = 3; // remaining = 10 - 3 = 7; we will compare 5 bytes by crafting:
        USHORT max_cmp = 5;
        for (USHORT i = 0; i < max_cmp; i++) k[depth + i] = (UCHAR)(baseStart + i);
        // put mismatch at the last compared byte (index 4)
        k[depth + (max_cmp - 1)] = (UCHAR)(baseStart + 0x44);

        USHORT r = check_prefix(n, k, 10, depth);
        TEST_ASSERT(r == (max_cmp - 1), "5.3: mismatch at last compared index");
        test_free_node_base(n);
    }

    DbgPrint("[INFO] Test 5: mismatch position handling validated\n");
    TEST_END("check_prefix: mismatch detection");
    return TRUE;
}

/* =========================================================
   Test 6: Depth edge cases
   Purpose:
     - (6.1) depth == key_length - 1 with matching single byte , returns 1
     - (6.2) depth == key_length , early 0 (already covered but explicit)
   ========================================================= */
BOOLEAN test_check_prefix_depth_edges()
{
    TEST_START("check_prefix: depth edge cases");

    // (6.1) remaining_key_length == 1 and it matches
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "6.1-pre: node alloc");
        n->prefix_length = 4; test_fill_prefix(n->prefix, 4, 0x90); // 90 91 92 93
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

    DbgPrint("[INFO] Test 6: depth edges validated\n");
    TEST_END("check_prefix: depth edge cases");
    return TRUE;
}

/* =========================================================
   Test 7: No alloc/free side-effects (sanity)
   Purpose:
     - Ensure check_prefix never allocates/frees
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
    (void)check_prefix(n, k, 32, (USHORT)(MAX_TREE_DEPTH + 1)); // early exit

    TEST_ASSERT(g_alloc_call_count == a0, "7: No allocations inside check_prefix");
    TEST_ASSERT(g_free_call_count == f0, "7: No frees inside check_prefix");

    test_free_node_base(n);

    DbgPrint("[INFO] Test 7: side-effects counters unchanged as expected\n");
    TEST_END("check_prefix: no alloc/free side-effects");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_check_prefix_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting check_prefix Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_check_prefix_param_validation())        all_passed = FALSE;
    if (!test_check_prefix_depth_and_zero_prefix())   all_passed = FALSE;
    if (!test_check_prefix_full_match())              all_passed = FALSE;
    if (!test_check_prefix_truncation_paths())        all_passed = FALSE;
    if (!test_check_prefix_mismatch_positions())      all_passed = FALSE;
    if (!test_check_prefix_depth_edges())             all_passed = FALSE;
    if (!test_check_prefix_no_allocfree_sideeffects())all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL check_prefix TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME check_prefix TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
