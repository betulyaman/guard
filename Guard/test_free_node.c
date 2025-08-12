#include "test_art.h"

STATIC inline VOID free_node(_Inout_ ART_NODE** node);

// ---------- Build-mode helper ----------
#if defined(DEBUG) || defined(DBG)
#  define ART_IS_DEBUG_BUILD 1
#else
#  define ART_IS_DEBUG_BUILD 0
#endif

// ---------- Local helpers ----------

// Allocate a minimal ART_NODE from NonPaged pool and set its type
static ART_NODE* test_alloc_node(NODE_TYPE type_to_set)
{
    ART_NODE* n = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
    if (n) {
        RtlZeroMemory(n, sizeof(ART_NODE));
        n->type = type_to_set;
    }
    return n;
}

// ========== Test 1: NULL parameter handling ==========
BOOLEAN test_free_node_null_pointer_handling()
{
    TEST_START("free_node: NULL Pointer Handling");
    reset_mock_state();

    // 1.1 node == NULL -> no free, no crash
#pragma warning(push)
#pragma warning(disable: 6387)
    free_node(NULL);
#pragma warning(pop)
    TEST_ASSERT(g_free_call_count == 0, "No free on NULL parameter");

    // 1.2 node != NULL but *node == NULL -> no-op
    ART_NODE* p = NULL;
    ART_NODE** pp = &p;
    free_node(pp);

    TEST_ASSERT(g_free_call_count == 0, "No free when *node is NULL");
    TEST_ASSERT(*pp == NULL, "Pointer remains NULL");

    TEST_END("free_node: NULL Pointer Handling");
    return TRUE;
}

// ========== Test 2: Valid pointer — free & null ==========
BOOLEAN test_free_node_valid_pointer_and_nulling()
{
    TEST_START("free_node: Valid Pointer Deallocation & Nulling");
    reset_mock_state();

    ART_NODE* n = test_alloc_node((NODE_TYPE)3);
    TEST_ASSERT(n != NULL, "Allocation for test node succeeded");
    ART_NODE** pn = &n;

    ULONG free_before = g_free_call_count;

    free_node(pn);

    // Must null the caller's pointer
    TEST_ASSERT(*pn == NULL, "Pointer-to-pointer must be set to NULL");
    TEST_ASSERT(g_free_call_count == free_before + 1, "Exactly one free must occur");
    TEST_ASSERT(g_last_freed_pointer != NULL, "Freed pointer captured");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "Must use ART_TAG for free");

    TEST_END("free_node: Valid Pointer Deallocation & Nulling");
    return TRUE;
}

// ========== Test 3: Idempotent behavior (double call) ==========
BOOLEAN test_free_node_idempotent_double_call()
{
    TEST_START("free_node: Idempotent Double Call");
    reset_mock_state();

    ART_NODE* n = test_alloc_node((NODE_TYPE)7);
    TEST_ASSERT(n != NULL, "Allocation for test node succeeded");
    ART_NODE** pn = &n;

    free_node(pn);   // first: frees & nulls
    free_node(pn);   // second: must be a no-op

    TEST_ASSERT(g_free_call_count == 1, "Only the first call should free");
    TEST_ASSERT(*pn == NULL, "Pointer remains NULL after second call");

    TEST_END("free_node: Idempotent Double Call");
    return TRUE;
}

// ========== Test 4: DEBUG poison (type=0xFF before free) ==========
BOOLEAN test_free_node_debug_poison_before_free()
{
    TEST_START("free_node: DEBUG Poison Before Free");
    reset_mock_state();

    ART_NODE* n = test_alloc_node((NODE_TYPE)2);
    TEST_ASSERT(n != NULL, "Allocation for test node succeeded");
    ART_NODE** pn = &n;

    ULONG free_before = g_free_call_count;
    free_node(pn);

#if ART_IS_DEBUG_BUILD
    TEST_ASSERT(g_last_freed_node_type_before_free == (UCHAR)0xFF,
        "In DEBUG build, node->type must be poisoned (0xFF) before free");
#else
    LOG_MSG("[INFO] Non-DEBUG build: poison before free is not mandatory; verifying free & NULL only\n");
#endif

    TEST_ASSERT(*pn == NULL, "Pointer is NULL after free");
    TEST_ASSERT(g_free_call_count == free_before + 1, "Exactly one free must occur");

    TEST_END("free_node: DEBUG Poison Before Free");
    return TRUE;
}

// ========== Test 5: Various node types (smoke over type values) ==========
BOOLEAN test_free_node_various_types()
{
    TEST_START("free_node: Various Node Types");
    static const UCHAR kTypes[] = { 0, 1, 2, 3, 4, 5, 15, 31, 63, 127, 255 };

    for (ULONG i = 0; i < RTL_NUMBER_OF(kTypes); ++i) {
        reset_mock_state();

        ART_NODE* n = test_alloc_node((NODE_TYPE)kTypes[i]);
        TEST_ASSERT(n != NULL, "Allocated node");
        ART_NODE** pn = &n;

        ULONG free_before = g_free_call_count;
        free_node(pn);

        TEST_ASSERT(*pn == NULL, "Pointer is NULL after free");
        TEST_ASSERT(g_free_call_count == free_before + 1, "Exactly one free must occur");

#if ART_IS_DEBUG_BUILD
        TEST_ASSERT(g_last_freed_node_type_before_free == (UCHAR)0xFF,
            "In DEBUG build, observed poisoned type (0xFF) before free");
#else
        LOG_MSG("[INFO] Non-DEBUG: poison check skipped (i=%lu, type=%u)\n", i, kTypes[i]);
#endif
    }

    TEST_END("free_node: Various Node Types");
    return TRUE;
}

// ========== Test 6: Bulk free in reverse order (order-independent) ==========
BOOLEAN test_free_node_bulk_reverse_order()
{
    TEST_START("free_node: Bulk Free in Reverse Order");
    reset_mock_state();

    const int N = 12;
    ART_NODE* nodes[12] = { 0 };   // init to NULL
    ART_NODE** addrs[12] = { 0 };  // init to NULL
    int alloc_count = 0;

    for (int i = 0; i < N; ++i) {
        nodes[i] = test_alloc_node((NODE_TYPE)(i & 0x0F));
        addrs[i] = &nodes[i];
        if (nodes[i]) ++alloc_count;
    }

    for (int i = N - 1; i >= 0; --i) {
        free_node(addrs[i]); // safe when *ptr == NULL
    }

    TEST_ASSERT(g_free_call_count == (ULONG)alloc_count, "Must free exactly the allocated nodes");

    for (int i = 0; i < N; ++i) {
        TEST_ASSERT(*addrs[i] == NULL, "Each pointer must be NULL after free");
    }

    TEST_END("free_node: Bulk Free in Reverse Order");
    return TRUE;
}

// ========== Test 7: Stress — many alloc/free cycles ==========
BOOLEAN test_free_node_stress_many_cycles()
{
    TEST_START("free_node: Stress Many Cycles");
    reset_mock_state();

    const int ITER = 100;
    int freed = 0;

    for (int i = 0; i < ITER; ++i) {
        ART_NODE* n = test_alloc_node((NODE_TYPE)(i & 0x07));
        if (n) {
            ART_NODE** pn = &n;
            free_node(pn);
            if (*pn == NULL) ++freed;
        }
        else {
            LOG_MSG("[INFO] Allocation failed at iteration %d (expected under stress)\n", i);
        }
    }

    TEST_ASSERT(g_free_call_count == (ULONG)freed, "Free count must match successful allocations");
    LOG_MSG("[INFO] Stress completed: freed %d / %d\n", freed, ITER);

    TEST_END("free_node: Stress Many Cycles");
    return TRUE;
}

// ========== Test 8: Logging guidance (visual/manual) ==========
BOOLEAN test_free_node_logging_guidance()
{
    TEST_START("free_node: Logging & Debugging (Visual)");
    reset_mock_state();

    // Allocate a few nodes and free while printing context to inspect LOG_MSG ordering
    for (int i = 0; i < 3; ++i) {
        ART_NODE* n = test_alloc_node((NODE_TYPE)(i + 42));
        if (n) {
            LOG_MSG("[TEST] About to free node #%d at %p (type=%d) — expect LOG_MSG before free\n",
                i, n, n->type);
            ART_NODE** pn = &n;
            free_node(pn);
            LOG_MSG("[TEST] free_node returned for node #%d\n", i);
        }
    }

    LOG_MSG("[INFO] Logging verification completed (check output ordering)\n");

    TEST_END("free_node: Logging & Debugging (Visual)");
    return TRUE;
}

// ========== Test 9: Safety — double-indirection isolates only the passed variable ==========
BOOLEAN test_free_node_pointer_isolation()
{
    TEST_START("free_node: Pointer Isolation Semantics");
    reset_mock_state();

    // Two distinct variables pointing to the same allocation (aliasing scenario)
    ART_NODE* a = test_alloc_node((NODE_TYPE)11);
    TEST_ASSERT(a != NULL, "Allocation succeeded");

    ART_NODE* alias = a;     // separate variable (will dangle after free)
    ART_NODE** pa = &a;

    free_node(pa);           // frees and sets 'a' to NULL
    TEST_ASSERT(*pa == NULL, "Primary pointer is NULL after free");

    // Do NOT call free_node(&alias); that would be a double-free. We only check semantics.
    TEST_ASSERT(alias != NULL, "Alias variable keeps stale value by design");
    LOG_MSG("[INFO] Alias pointer intentionally left dangling to validate API semantics\n");

    TEST_ASSERT(g_free_call_count == 1, "Only one free must occur");

    TEST_END("free_node: Pointer Isolation Semantics");
    return TRUE;
}

// ========== Test 10: Tiny/edge allocations (structure sized) ==========
BOOLEAN test_free_node_edge_allocations()
{
    TEST_START("free_node: Edge Allocations");
    reset_mock_state();

    // Exactly sizeof(ART_NODE); touch pattern before free
    ART_NODE* n = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
    if (n) {
        RtlFillMemory(n, sizeof(ART_NODE), 0xA5);
        n->type = (NODE_TYPE)5; // ensure type set after fill
        ART_NODE** pn = &n;

        ULONG free_before = g_free_call_count;
        free_node(pn);

        TEST_ASSERT(*pn == NULL, "Pointer NULL after free");
        TEST_ASSERT(g_free_call_count == free_before + 1, "Freed once");
        TEST_ASSERT(g_last_freed_tag == ART_TAG, "Used ART_TAG");

#if ART_IS_DEBUG_BUILD
        TEST_ASSERT(g_last_freed_node_type_before_free == (UCHAR)0xFF,
            "In DEBUG, poisoned type (0xFF) must be seen before free");
#else
        LOG_MSG("[INFO] Non-DEBUG: poison check skipped in edge allocation test\n");
#endif
    }
    else {
        LOG_MSG("[TEST SKIP] Could not allocate ART_NODE for edge test\n");
    }

    TEST_END("free_node: Edge Allocations");
    return TRUE;
}

// -------------- Runner for free_node --------------
NTSTATUS run_all_free_node_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting Comprehensive free_node Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_free_node_null_pointer_handling())     all_passed = FALSE;
    if (!test_free_node_valid_pointer_and_nulling()) all_passed = FALSE;
    if (!test_free_node_idempotent_double_call())    all_passed = FALSE;
    if (!test_free_node_debug_poison_before_free())  all_passed = FALSE;
    if (!test_free_node_various_types())             all_passed = FALSE;
    if (!test_free_node_bulk_reverse_order())        all_passed = FALSE;
    if (!test_free_node_stress_many_cycles())        all_passed = FALSE;
    if (!test_free_node_logging_guidance())          all_passed = FALSE;
    if (!test_free_node_pointer_isolation())         all_passed = FALSE;
    if (!test_free_node_edge_allocations())          all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL free_node TESTS PASSED! \n");
    }
    else {
        LOG_MSG("SOME free_node TESTS FAILED! \n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
