#include "test_art.h"

STATIC NTSTATUS art_init_tree(ART_TREE* tree);

/* =========================================================================
   Test 1: NULL pointer handling
   Purpose:
     - Passing NULL must return STATUS_INVALID_PARAMETER and perform no work.
   Sub-checks:
     (1.1) Returns STATUS_INVALID_PARAMETER
     (1.2) No allocations happen
     (1.3) No frees happen
   ========================================================================= */
BOOLEAN test_art_init_tree_null_parameter()
{
    TEST_START("art_init_tree: NULL parameter");

    reset_mock_state();

    NTSTATUS st = art_init_tree(NULL);

    // (1.1)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: Must return STATUS_INVALID_PARAMETER for NULL");

    // (1.2)
    TEST_ASSERT(g_alloc_call_count == 0, "1.2: No allocations for NULL parameter");

    // (1.3)
    TEST_ASSERT(g_free_call_count == 0, "1.3: No frees for NULL parameter");

    DbgPrint("[INFO] Test 1: NULL input safely rejected without side effects\n");
    TEST_END("art_init_tree: NULL parameter");
    return TRUE;
}

/* =========================================================================
   Test 2: Fresh init on a junk-filled struct
   Purpose:
     - tree->root must become NULL, tree->size must become 0.
     - Should not allocate or free anything.
   Sub-checks:
     (2.1) Returns STATUS_SUCCESS
     (2.2) root == NULL
     (2.3) size == 0
     (2.4) No allocations
     (2.5) No frees
   ========================================================================= */
BOOLEAN test_art_init_tree_basic_zeroing()
{
    TEST_START("art_init_tree: basic zeroing behavior");

    reset_mock_state();

    ART_TREE tree;
    RtlFillMemory(&tree, sizeof(tree), 0xA5); // ensure fields are overwritten

    NTSTATUS st = art_init_tree(&tree);

    // (2.1)
    TEST_ASSERT(st == STATUS_SUCCESS, "2.1: Must return STATUS_SUCCESS");

    // (2.2)
    TEST_ASSERT(tree.root == NULL, "2.2: root must be set to NULL");

    // (2.3)
    TEST_ASSERT(tree.size == 0, "2.3: size must be set to 0");

    // (2.4) (2.5)
    TEST_ASSERT(g_alloc_call_count == 0, "2.4: No allocations should occur");
    TEST_ASSERT(g_free_call_count == 0, "2.5: No frees should occur");

    DbgPrint("[INFO] Test 2: tree initialized to a clean state (root=NULL, size=0)\n");
    TEST_END("art_init_tree: basic zeroing behavior");
    return TRUE;
}

/* =========================================================================
   Test 3: Idempotency / re-initialization
   Purpose:
     - Repeated calls must keep the tree in a clean state.
     - Must not allocate/free.
   Sub-checks:
     (3.1) First call returns STATUS_SUCCESS and zeroes fields
     (3.2) Modify fields, second call re-zeroes them
     (3.3) No allocations across both calls
     (3.4) No frees across both calls
   ========================================================================= */
BOOLEAN test_art_init_tree_idempotency()
{
    TEST_START("art_init_tree: idempotency");

    reset_mock_state();

    ART_TREE tree;
    RtlZeroMemory(&tree, sizeof(tree));

    // First call on already-zero state
    NTSTATUS st1 = art_init_tree(&tree);
    TEST_ASSERT(st1 == STATUS_SUCCESS, "3.1: First call returns STATUS_SUCCESS");
    TEST_ASSERT(tree.root == NULL && tree.size == 0, "3.1: Fields zero after first call");

    // Dirty the struct artificially
    tree.root = (ART_NODE*)(ULONG_PTR)0x1234;
    tree.size = (ULONG_PTR)0x5678;

    // Second call must clean it again
    NTSTATUS st2 = art_init_tree(&tree);
    TEST_ASSERT(st2 == STATUS_SUCCESS, "3.2: Second call returns STATUS_SUCCESS");
    TEST_ASSERT(tree.root == NULL && tree.size == 0, "3.2: Fields re-zeroed after second call");

    TEST_ASSERT(g_alloc_call_count == 0, "3.3: No allocations across repeated calls");
    TEST_ASSERT(g_free_call_count == 0, "3.4: No frees across repeated calls");

    DbgPrint("[INFO] Test 3: repeated initialization keeps tree clean without allocations\n");
    TEST_END("art_init_tree: idempotency");
    return TRUE;
}

/* =========================================================================
   Test 4: Does not free existing content
   Purpose:
     - If tree->root already points to a node, art_init_tree must NOT free it.
       (The function is an initializer, not a destructor.)
   Sub-checks:
     (4.1) Returns STATUS_SUCCESS
     (4.2) Sets root=NULL and size=0
     (4.3) Does NOT free the existing node (free counter unchanged)
     (4.4) After test, we manually free the node and free counter increases
   ========================================================================= */
BOOLEAN test_art_init_tree_does_not_free_existing_root()
{
    TEST_START("art_init_tree: does not free existing root");

    reset_mock_state();

    ART_TREE tree;
    RtlZeroMemory(&tree, sizeof(tree));

    // Attach a real allocation so we can verify it is not freed by art_init_tree
    ART_NODE* n = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(n != NULL, "4.pre: Dummy node allocation succeeded");
    tree.root = n;
    tree.size = 123; // arbitrary non-zero

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = art_init_tree(&tree);

    // (4.1)
    TEST_ASSERT(st == STATUS_SUCCESS, "4.1: Returns STATUS_SUCCESS");

    // (4.2)
    TEST_ASSERT(tree.root == NULL && tree.size == 0, "4.2: root=NULL and size=0 after init");

    // (4.3)
    TEST_ASSERT(g_free_call_count == frees_before, "4.3: art_init_tree must not free existing root");

    // Manually free the node now to avoid a leak in test
    ExFreePoolWithTag(n, ART_TAG);
    TEST_ASSERT(g_free_call_count == frees_before + 1, "4.4: Manual cleanup increments free counter");

    DbgPrint("[INFO] Test 4: initializer does not perform ownership cleanup (as expected)\n");
    TEST_END("art_init_tree: does not free existing root");
    return TRUE;
}

/* =========================================================================
   Test 5: Non-allocating behavior across many trees
   Purpose:
     - Initialize many trees (with varied junk) and confirm no allocations.
   Sub-checks:
     (5.1) Each call returns STATUS_SUCCESS
     (5.2) Each tree ends with root=NULL, size=0
     (5.3) No allocations across the batch
     (5.4) No frees across the batch
   ========================================================================= */
BOOLEAN test_art_init_tree_many_without_allocs()
{
    TEST_START("art_init_tree: many init calls without allocations");

    reset_mock_state();

    ART_TREE trees[64];

    // Fill with varied junk (N)
    for (int i = 0; i < 64; ++i) {
        RtlFillMemory(&trees[i], sizeof(ART_TREE), (UCHAR)(0x10 + (i & 0x7F)));
        // Also flip in some arbitrary, non-dereferenced root values
        trees[i].root = (ART_NODE*)(ULONG_PTR)(i | 0x1);
        trees[i].size = (ULONG_PTR)(i * 3 + 1);
    }

    for (int i = 0; i < 64; ++i) {
        NTSTATUS st = art_init_tree(&trees[i]);
        // (5.1)
        TEST_ASSERT(st == STATUS_SUCCESS, "5.1: STATUS_SUCCESS for each tree");
        // (5.2)
        TEST_ASSERT(trees[i].root == NULL && trees[i].size == 0,
            "5.2: Each tree ends clean (root=NULL,size=0)");
    }

    // (5.3) (5.4)
    TEST_ASSERT(g_alloc_call_count == 0, "5.3: No allocations across batch init");
    TEST_ASSERT(g_free_call_count == 0, "5.4: No frees across batch init");

    DbgPrint("[INFO] Test 5: batch initialization performed with zero allocations and frees\n");
    TEST_END("art_init_tree: many init calls without allocations");
    return TRUE;
}

/* =========================================================================
   Runner for art_init_tree tests
   ========================================================================= */
NTSTATUS run_all_art_init_tree_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting art_init_tree Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_art_init_tree_null_parameter())            all_passed = FALSE;
    if (!test_art_init_tree_basic_zeroing())             all_passed = FALSE;
    if (!test_art_init_tree_idempotency())               all_passed = FALSE;
    if (!test_art_init_tree_does_not_free_existing_root()) all_passed = FALSE;
    if (!test_art_init_tree_many_without_allocs())       all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL art_init_tree TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME art_init_tree TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
