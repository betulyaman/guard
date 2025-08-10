#include "test_art.h"

// Function under test
STATIC inline VOID free_leaf(_Inout_ ART_LEAF** leaf);

// Mock captures (provided by the shared header/mocks)

extern USHORT g_last_freed_leaf_keylen_before_free; // captured before ExFreePoolWithTag
extern ULONG  g_debugbreak_count;                   // __debugbreak() hit counter (DEBUG path)

/*========================================================
  Test 1: NULL and no-op handling
  - leaf == NULL          -> no free, no crash
  - *leaf == NULL (no-op) -> no free, pointer stays NULL
========================================================*/
BOOLEAN test_free_leaf_null_and_noop()
{
    TEST_START("free_leaf: NULL and no-op");
    reset_mock_state();

    // 1.1 leaf == NULL
#pragma warning(push)
#pragma warning(disable: 6387)
    free_leaf(NULL);
#pragma warning(pop)

    TEST_ASSERT(g_free_call_count == 0, "No free when leaf==NULL");


    // 1.2 *leaf == NULL
    ART_LEAF* p = NULL;
    ART_LEAF** pp = &p;
    free_leaf(pp);

    TEST_ASSERT(g_free_call_count == 0, "No free when *leaf==NULL");

    TEST_ASSERT(*pp == NULL, "Pointer remains NULL");

    TEST_END("free_leaf: NULL and no-op");
    return TRUE;
}

/*========================================================
  Test 2: Valid free -> frees exactly once and NULLs pointer
========================================================*/
BOOLEAN test_free_leaf_valid_free_and_nulling()
{
    TEST_START("free_leaf: valid free & nulling");
    reset_mock_state();

    ART_LEAF* lf = test_alloc_leaf((USHORT)42, 0x00); // FIX: add start_val
    TEST_ASSERT(lf != NULL, "Leaf allocation succeeded");
    ART_LEAF** plf = &lf;

    free_leaf(plf);

    TEST_ASSERT(*plf == NULL, "Pointer-to-pointer must be set to NULL after free");

    TEST_ASSERT(g_free_call_count == 1, "Exactly one free must occur");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "Must use ART_TAG for free");

    TEST_ASSERT(g_last_freed_leaf_keylen_before_free == LEAF_FREED_MAGIC,
        "DEBUG: key_length must be poisoned (LEAF_FREED_MAGIC) before free");



    TEST_END("free_leaf: valid free & nulling");
    return TRUE;
}

/*========================================================
  Test 3: Idempotency (double call)
  - first call frees & NULLs
  - second call is a no-op
========================================================*/
BOOLEAN test_free_leaf_idempotent_double_call()
{
    TEST_START("free_leaf: idempotent double call");
    reset_mock_state();

    ART_LEAF* lf = test_alloc_leaf((USHORT)10, 0x00); // FIX: add start_val
    TEST_ASSERT(lf != NULL, "Leaf allocation succeeded");
    ART_LEAF** plf = &lf;

    free_leaf(plf);
    free_leaf(plf); // must be no-op


    TEST_ASSERT(g_free_call_count == 1, "Second call must be a no-op");

    TEST_ASSERT(*plf == NULL, "Pointer remains NULL");

    TEST_END("free_leaf: idempotent double call");
    return TRUE;
}

/*========================================================
  Test 4: Double-free detection path (DEBUG)
  - If key_length == LEAF_FREED_MAGIC on entry:
      * Warn + __debugbreak()
      * Still free once and NULL pointer
========================================================*/
BOOLEAN test_free_leaf_double_free_detection_path()
{
    TEST_START("free_leaf: double-free detection path");
    reset_mock_state();

    // simulate "already poisoned" leaf (as if double-free)
    ART_LEAF* lf = test_alloc_leaf((USHORT)8, 0x00); // FIX: allocate normal size
    TEST_ASSERT(lf != NULL, "Leaf allocation succeeded");
    lf->key_length = LEAF_FREED_MAGIC; // FIX: poison after allocation
    ART_LEAF** plf = &lf;

    free_leaf(plf);



    TEST_ASSERT(g_debugbreak_count == 1, "__debugbreak must be hit once on detection");
    TEST_ASSERT(g_free_call_count == 1, "Leaf must still be freed exactly once");
    TEST_ASSERT(g_last_freed_leaf_keylen_before_free == LEAF_FREED_MAGIC, "Poison value observed before free");

    TEST_ASSERT(*plf == NULL, "Pointer NULL after free");

    TEST_END("free_leaf: double-free detection path");
    return TRUE;
}

/*========================================================
  Test 5: Bulk free (reverse order) — order independence
========================================================*/
BOOLEAN test_free_leaf_bulk_reverse_order()
{
    TEST_START("free_leaf: bulk reverse order");
    reset_mock_state();

    const int N = 12;
    ART_LEAF* arr[12] = { 0 };   // init to NULL
    ART_LEAF** addrs[12] = { 0 };  // init to NULL
    int allocs = 0;

    for (int i = 0; i < N; ++i) {
        arr[i] = test_alloc_leaf((USHORT)(i + 1), (UCHAR)i);
        addrs[i] = &arr[i];                // always set address
        if (arr[i]) ++allocs;              // count only successful allocs
    }

    for (int i = N - 1; i >= 0; --i) {
        free_leaf(addrs[i]);               // safe: free_leaf handles *ptr==NULL as no-op
    }

    TEST_ASSERT(g_free_call_count == (ULONG)allocs, "Free count must match allocations");

    TEST_ASSERT(g_last_freed_leaf_keylen_before_free == LEAF_FREED_MAGIC,
        "Last freed leaf observed poisoned before free");

    for (int i = 0; i < N; ++i) {
        TEST_ASSERT(*addrs[i] == NULL, "Each pointer must be NULL after free");
    }

    TEST_END("free_leaf: bulk reverse order");
    return TRUE;
}

/*========================================================
  Test 6: Stress — many alloc/free cycles
========================================================*/
BOOLEAN test_free_leaf_stress_many_cycles()
{
    TEST_START("free_leaf: stress many cycles");
    reset_mock_state();

    const int ITER = 100;
    int freed = 0;

    for (int i = 0; i < ITER; ++i) {
        ART_LEAF* lf = test_alloc_leaf((USHORT)(1000 + i), 0x55); // FIX: add start_val
        if (lf) {
            ART_LEAF** plf = &lf;
            free_leaf(plf);
            if (*plf == NULL) ++freed;
        }
        else {
            DbgPrint("[INFO] Allocation failed at iteration %d (expected under stress)\n", i);
        }
    }


    TEST_ASSERT(g_free_call_count == (ULONG)freed, "All successfully allocated leaves must be freed");

    DbgPrint("[INFO] Stress completed: freed %d/%d\n", freed, ITER);

    TEST_END("free_leaf: stress many cycles");
    return TRUE;
}

/*========================================================
  Test 7: Logging (visual aid)
========================================================*/
BOOLEAN test_free_leaf_logging_visual()
{
    TEST_START("free_leaf: logging (visual)");
    reset_mock_state();

    for (int i = 0; i < 3; ++i) {
        ART_LEAF* lf = test_alloc_leaf((USHORT)(200 + i), 0xA0); // FIX: add start_val
        if (lf) {
            DbgPrint("[TEST] about to free leaf #%d at %p (key_length=%hu) — expect LOG_MSG\n",
                i, lf, lf->key_length);
            ART_LEAF** plf = &lf;
            free_leaf(plf);
            DbgPrint("[TEST] free_leaf returned for leaf #%d\n", i);
        }
    }

    DbgPrint("[INFO] Logging verification completed (check output ordering)\n");
    TEST_END("free_leaf: logging (visual)");
    return TRUE;
}

/*========================================================
  Test 8: Pointer isolation semantics
  - Two variables alias same allocation; only the one
    passed by address is NULLed; the other dangles.
========================================================*/
BOOLEAN test_free_leaf_pointer_isolation()
{
    TEST_START("free_leaf: pointer isolation semantics");
    reset_mock_state();

    ART_LEAF* a = test_alloc_leaf((USHORT)321, 0x00); // FIX: add start_val
    TEST_ASSERT(a != NULL, "Leaf allocation succeeded");

    ART_LEAF* alias = a;   // separate variable (will dangle)
    ART_LEAF** pa = &a;

    free_leaf(pa);
    TEST_ASSERT(*pa == NULL, "Primary pointer is NULL after free");
    TEST_ASSERT(alias != NULL, "Alias retains stale value (by design)");

    TEST_ASSERT(g_free_call_count == 1, "Freed exactly once");


    TEST_END("free_leaf: pointer isolation semantics");
    return TRUE;
}

/*========================================================
  Runner: free_leaf
========================================================*/
NTSTATUS run_all_free_leaf_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting Comprehensive free_leaf Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_free_leaf_null_and_noop())                 all_passed = FALSE;
    if (!test_free_leaf_valid_free_and_nulling())        all_passed = FALSE;
    if (!test_free_leaf_idempotent_double_call())        all_passed = FALSE;
    if (!test_free_leaf_double_free_detection_path())    all_passed = FALSE;
    if (!test_free_leaf_bulk_reverse_order())            all_passed = FALSE;
    if (!test_free_leaf_stress_many_cycles())            all_passed = FALSE;
    if (!test_free_leaf_logging_visual())                all_passed = FALSE;
    if (!test_free_leaf_pointer_isolation())             all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL free_leaf TESTS PASSED! \n");
    }
    else {
        DbgPrint("SOME free_leaf TESTS FAILED! \n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
