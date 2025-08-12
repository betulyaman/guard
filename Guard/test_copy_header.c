#include "test_art.h"

// Function under test
STATIC NTSTATUS copy_header(_Inout_ ART_NODE* dest, _In_ ART_NODE* src);

//-------------------------
// Small helpers
//-------------------------

static VOID test_free_node_base(ART_NODE* n)
{
    if (n) ExFreePool2(n, ART_TAG, NULL, 0);
}

static VOID test_fill_prefix(UCHAR* dst, USHORT len, UCHAR start)
{
    // Fill with deterministic pattern: start, start+1, ...
    for (USHORT i = 0; i < len; ++i) {
        dst[i] = (UCHAR)(start + (UCHAR)i);
    }
}

BOOLEAN test_bytes_eq(const UCHAR* a, const UCHAR* b, SIZE_T len)
{

    return (RtlCompareMemory(a, b, len) == len) ? TRUE : FALSE;
}

/* =========================================================
   Test 1: NULL parameter handling
   Purpose:
     - If either dest or src is NULL, return STATUS_INVALID_PARAMETER
     - Dest must remain untouched when src is NULL
     - No alloc/free inside the function
   Sub-checks:
     (1.1) dest==NULL, src valid
     (1.2) src==NULL, dest valid (verify dest unchanged)
   ========================================================= */
BOOLEAN test_copy_header_null_params()
{
    TEST_START("copy_header: NULL parameter handling");

    // (1.1) dest==NULL
    reset_mock_state();
    {
        ART_NODE* src = test_alloc_node_base();
        TEST_ASSERT(src != NULL, "1.1-pre: allocate src");
        src->num_of_child = 3;
        src->prefix_length = 2;
        test_fill_prefix(src->prefix, (USHORT)min(src->prefix_length, (USHORT)MAX_PREFIX_LENGTH), 0x10);

        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable: 6387)
        NTSTATUS st = copy_header(NULL, src);
#pragma warning(pop)
        TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: dest==NULL should fail with STATUS_INVALID_PARAMETER");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.1: No alloc/free inside copy_header");
        test_free_node_base(src);
    }

    // (1.2) src==NULL, dest must remain untouched
    reset_mock_state();
    {
        ART_NODE* dest = test_alloc_node_base();
        TEST_ASSERT(dest != NULL, "1.2-pre: allocate dest");
        dest->num_of_child = 9;
        dest->prefix_length = 7;
        UCHAR before[MAX_PREFIX_LENGTH];
        for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) { dest->prefix[i] = (UCHAR)(0xA0 + i); before[i] = dest->prefix[i]; }

        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable: 6387)
        NTSTATUS st = copy_header(dest, NULL);
#pragma warning(pop)
        TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: src==NULL should fail");
        TEST_ASSERT(dest->num_of_child == 9 && dest->prefix_length == 7, "1.2: dest fields must remain unchanged");
        TEST_ASSERT(test_bytes_eq(dest->prefix, before, MAX_PREFIX_LENGTH), "1.2: dest->prefix must remain unchanged");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.2: No alloc/free inside copy_header");

        test_free_node_base(dest);
    }

    LOG_MSG("[INFO] Test 1 done: NULL parameter paths verified\n");
    TEST_END("copy_header: NULL parameter handling");
    return TRUE;
}

/* =========================================================
   Test 2: Zero-length prefix (no copy of bytes)
   Purpose:
     - Copy num_of_child and prefix_length=0
     - Leave dest->prefix bytes untouched
   Sub-checks:
     (2.1) src->prefix_length=0 , dest->prefix unchanged
   ========================================================= */
BOOLEAN test_copy_header_zero_length_prefix()
{
    TEST_START("copy_header: zero-length prefix");

    reset_mock_state();

    ART_NODE* src = test_alloc_node_base();
    ART_NODE* dest = test_alloc_node_base();
    TEST_ASSERT(src && dest, "2.1-pre: allocate nodes");

    // Prepare src
    src->num_of_child = 4;
    src->prefix_length = 0;
    test_fill_prefix(src->prefix, MAX_PREFIX_LENGTH, 0x11); // won't be used

    // Prepare dest with known pattern
    dest->num_of_child = 77;
    dest->prefix_length = 9;
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) dest->prefix[i] = 0xAA;

    // Keep a snapshot of dest->prefix to verify it stays untouched
    UCHAR before[MAX_PREFIX_LENGTH];
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) before[i] = dest->prefix[i];

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    NTSTATUS st = copy_header(dest, src);

    TEST_ASSERT(st == STATUS_SUCCESS, "2.1: return STATUS_SUCCESS");
    TEST_ASSERT(dest->num_of_child == 4, "2.1: num_of_child copied");
    TEST_ASSERT(dest->prefix_length == 0, "2.1: prefix_length set to 0");
    TEST_ASSERT(test_bytes_eq(dest->prefix, before, MAX_PREFIX_LENGTH),"2.1: dest->prefix bytes remain untouched (pattern 0xAA)");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "2.1: No alloc/free inside");

    test_free_node_base(src);
    test_free_node_base(dest);

    LOG_MSG("[INFO] Test 2 done: zero-length prefix leaves prefix bytes intact\n");
    TEST_END("copy_header: zero-length prefix");
    return TRUE;
}

/* =========================================================
   Test 3: In-bounds copy (no truncation)
   Purpose:
     - src->prefix_length <= MAX_PREFIX_LENGTH
     - First 'len' bytes copied; bytes beyond 'len' in dest remain as before
   Sub-checks:
     (3.1) len = 5 (example) , copy first 5 bytes, keep the rest
   ========================================================= */
BOOLEAN test_copy_header_inbounds_copy()
{
    TEST_START("copy_header: in-bounds copy");

    reset_mock_state();

    ART_NODE* src = test_alloc_node_base();
    ART_NODE* dest = test_alloc_node_base();
    TEST_ASSERT(src && dest, "3.1-pre: allocate nodes");

    const USHORT len = (MAX_PREFIX_LENGTH >= 5) ? 5 : MAX_PREFIX_LENGTH;
    TEST_ASSERT(len > 0, "3.1-pre: need len > 0 (MAX_PREFIX_LENGTH must be >=1)");

    // Prepare src
    src->num_of_child = 2;
    src->prefix_length = len;
    test_fill_prefix(src->prefix, len, 0x20); // 0x20,0x21,...

    // Prepare dest (pattern 0xAA)
    dest->num_of_child = 88;
    dest->prefix_length = 13;
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) dest->prefix[i] = 0xAA;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    NTSTATUS st = copy_header(dest, src);

    TEST_ASSERT(st == STATUS_SUCCESS, "3.1: return STATUS_SUCCESS");
    TEST_ASSERT(dest->num_of_child == 2, "3.1: num_of_child copied");
    TEST_ASSERT(dest->prefix_length == len, "3.1: prefix_length copied (no truncation)");

    // Check first 'len' bytes equal to src
    TEST_ASSERT(test_bytes_eq(dest->prefix, src->prefix, len), "3.1: first len bytes copied");

    // Check bytes beyond 'len' remain 0xAA
    if (len < MAX_PREFIX_LENGTH) {
        for (USHORT i = len; i < MAX_PREFIX_LENGTH; ++i) {
            TEST_ASSERT(dest->prefix[i] == 0xAA, "3.1: bytes beyond len remain untouched");
        }
    }

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "3.1: No alloc/free inside");

    test_free_node_base(src);
    test_free_node_base(dest);

    LOG_MSG("[INFO] Test 3 done: in-bounds copy correct and non-destructive beyond len\n");
    TEST_END("copy_header: in-bounds copy");
    return TRUE;
}

/* =========================================================
   Test 4: Truncation path (src->prefix_length > MAX_PREFIX_LENGTH)
   Purpose:
     - Copy exactly MAX_PREFIX_LENGTH bytes
     - Set dest->prefix_length to MAX_PREFIX_LENGTH
     - Do not modify bytes beyond MAX_PREFIX_LENGTH
   Sub-checks:
     (4.1) len = MAX_PREFIX_LENGTH + 5 , truncates to MAX_PREFIX_LENGTH
   ========================================================= */
BOOLEAN test_copy_header_truncation()
{
    TEST_START("copy_header: truncation path");

    reset_mock_state();

    ART_NODE* src = test_alloc_node_base();
    ART_NODE* dest = test_alloc_node_base();
    TEST_ASSERT(src && dest, "4.1-pre: allocate nodes");

    const USHORT over = (USHORT)(MAX_PREFIX_LENGTH + 5);

    // Prepare src with over-length
    src->num_of_child = 7;
    src->prefix_length = over;
    test_fill_prefix(src->prefix, MAX_PREFIX_LENGTH, 0x40); // only first MAX_PREFIX_LENGTH will be read

    // Prepare dest pattern
    dest->num_of_child = 99;
    dest->prefix_length = 3;
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; ++i) dest->prefix[i] = 0xAA;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    NTSTATUS st = copy_header(dest, src);

    TEST_ASSERT(st == STATUS_SUCCESS, "4.1: return STATUS_SUCCESS");
    TEST_ASSERT(dest->num_of_child == 7, "4.1: num_of_child copied");
    TEST_ASSERT(dest->prefix_length == MAX_PREFIX_LENGTH, "4.1: prefix_length truncated to MAX_PREFIX_LENGTH");

    // First MAX_PREFIX_LENGTH bytes equal to src’s first MAX_PREFIX_LENGTH bytes
    TEST_ASSERT(test_bytes_eq(dest->prefix, src->prefix, MAX_PREFIX_LENGTH),
        "4.1: prefix copied up to MAX_PREFIX_LENGTH");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "4.1: No alloc/free inside");

    test_free_node_base(src);
    test_free_node_base(dest);

    LOG_MSG("[INFO] Test 4 done: truncation sets length and copies exactly MAX_PREFIX_LENGTH bytes\n");
    TEST_END("copy_header: truncation path");
    return TRUE;
}

/* =========================================================
   Test 5: Self-copy (dest == src)
   Purpose:
     - Calling copy_header on the same node should be a no-op w.r.t. content
       (fields equal before/after; RtlCopyMemory with identical regions is OK)
   Sub-checks:
     (5.1) dest==src, len within bounds
     (5.2) dest==src, len > MAX_PREFIX_LENGTH (truncation still results in same observable state)
   ========================================================= */
BOOLEAN test_copy_header_self_copy()
{
    TEST_START("copy_header: self-copy (dest == src)");

    // (5.1) within bounds
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base();
        TEST_ASSERT(n != NULL, "5.1-pre: allocate node");
        n->num_of_child = 12;
        n->prefix_length = (MAX_PREFIX_LENGTH >= 6) ? 6 : MAX_PREFIX_LENGTH;
        test_fill_prefix(n->prefix, (USHORT)min(n->prefix_length, (USHORT)MAX_PREFIX_LENGTH), 0x55);

        ART_NODE before = *n; // shallow copy (prefix inline)
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        NTSTATUS st = copy_header(n, n);
        TEST_ASSERT(st == STATUS_SUCCESS, "5.1: return STATUS_SUCCESS");
        TEST_ASSERT(RtlCompareMemory(&before, n, sizeof(ART_NODE)) == sizeof(ART_NODE),
            "5.1: node unchanged after self-copy");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "5.1: No alloc/free inside");

        test_free_node_base(n);
    }

    // (5.2) logical “over” length scenario: simulate by setting prefix_length>MAX then self-copy
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base();
        TEST_ASSERT(n != NULL, "5.2-pre: allocate node");
        n->num_of_child = 1;
        n->prefix_length = (USHORT)(MAX_PREFIX_LENGTH + 10);
        test_fill_prefix(n->prefix, MAX_PREFIX_LENGTH, 0x70);

        // Expected outcome after call: prefix_length becomes MAX_PREFIX_LENGTH
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        NTSTATUS st = copy_header(n, n);
        TEST_ASSERT(st == STATUS_SUCCESS, "5.2: return STATUS_SUCCESS");
        TEST_ASSERT(n->prefix_length == MAX_PREFIX_LENGTH, "5.2: length truncated to MAX_PREFIX_LENGTH on self-copy");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "5.2: No alloc/free inside");

        test_free_node_base(n);
    }

    LOG_MSG("[INFO] Test 5 done: self-copy scenarios behave correctly\n");
    TEST_END("copy_header: self-copy (dest == src)");
    return TRUE;
}

/* =========================================================
   Test 6: No alloc/free side-effects (sanity)
   Purpose:
     - Ensure copy_header itself never allocates/frees
   Sub-checks:
     (6.1) Counters unchanged across several calls
   ========================================================= */
BOOLEAN test_copy_header_no_allocfree_sideeffects()
{
    TEST_START("copy_header: no alloc/free side-effects");

    reset_mock_state();

    ART_NODE* a = test_alloc_node_base();
    ART_NODE* b = test_alloc_node_base();
    ART_NODE* c = test_alloc_node_base();
    TEST_ASSERT(a && b && c, "6.1-pre: allocate 3 nodes");

    a->num_of_child = 1; a->prefix_length = 0;
    b->num_of_child = 2; b->prefix_length = (USHORT)min(3, (int)MAX_PREFIX_LENGTH);
    c->num_of_child = 9; c->prefix_length = (USHORT)min(MAX_PREFIX_LENGTH, 7);
    test_fill_prefix(b->prefix, b->prefix_length, 0x10);
    test_fill_prefix(c->prefix, c->prefix_length, 0x20);

    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    // Several calls with different shapes
    TEST_ASSERT(copy_header(a, b) == STATUS_SUCCESS, "6.1: a<-b");
    TEST_ASSERT(copy_header(b, a) == STATUS_SUCCESS, "6.1: b<-a");
    TEST_ASSERT(copy_header(c, c) == STATUS_SUCCESS, "6.1: c<-c");

    TEST_ASSERT(g_alloc_call_count == alloc_before, "6.1: no allocations inside copy_header");
    TEST_ASSERT(g_free_call_count == free_before, "6.1: no frees inside copy_header");

    test_free_node_base(a);
    test_free_node_base(b);
    test_free_node_base(c);

    LOG_MSG("[INFO] Test 6 done: no alloc/free side-effects confirmed\n");
    TEST_END("copy_header: no alloc/free side-effects");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_copy_header_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting copy_header Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_copy_header_null_params())              all_passed = FALSE;
    if (!test_copy_header_zero_length_prefix())       all_passed = FALSE;
    if (!test_copy_header_inbounds_copy())            all_passed = FALSE;
    if (!test_copy_header_truncation())               all_passed = FALSE;
    if (!test_copy_header_self_copy())                all_passed = FALSE;
    if (!test_copy_header_no_allocfree_sideeffects()) all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL copy_header TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME copy_header TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
