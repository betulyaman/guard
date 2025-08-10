#include "test_art.h"

// Function under test
STATIC NTSTATUS add_child256(_Inout_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);

/* =========================================================
   Test 1: Guard checks
   Covers:
     (1.1) node == NULL , STATUS_INVALID_PARAMETER
     (1.2) child == NULL , STATUS_INVALID_PARAMETER
     (1.3) depth/‘ref’ is ignored by API (ensure passing any ref doesn’t matter)
   Also: no alloc/free side-effects.
   ========================================================= */
BOOLEAN test_add_child256_guards()
{
    TEST_START("add_child256: guards");

    reset_mock_state();

    ART_NODE* dummy_child = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(dummy_child != NULL, "1-pre: allocate dummy child");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    // (1.1) node == NULL
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256(NULL, NULL, 0, dummy_child);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node must be rejected");

    // (1.2) child == NULL
    ART_NODE256* n = t_alloc_node256(); TEST_ASSERT(n, "1.2-pre: node alloc");
    n->base.type = NODE256;
#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child256(n, NULL, 0, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL child must be rejected");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no alloc/free inside add_child256");

    t_free(n);
    t_free(dummy_child);

    TEST_END("add_child256: guards");
    return TRUE;
}

/* =========================================================
   Test 2: Wrong node type
   Case:
     - node->base.type != NODE256 , STATUS_INVALID_PARAMETER
   ========================================================= */
BOOLEAN test_add_child256_wrong_type()
{
    TEST_START("add_child256: wrong node type");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4();
    ART_NODE* child = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n4 && child, "2-pre: alloc inputs");
    n4->base.type = NODE4;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256((ART_NODE256*)n4, NULL, 10, child);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: non-NODE256 must be rejected");
    // Ensure the node wasn’t mutated
    TEST_ASSERT(n4->base.num_of_child == 0, "2.2: num_of_child must remain 0 on reject");

    t_free(child);
    t_free(n4);

    TEST_END("add_child256: wrong node type");
    return TRUE;
}

/* =========================================================
   Test 3: Occupied slot (collision)
   Case:
     - children[c] already non-NULL , STATUS_OBJECT_NAME_COLLISION
     - num_of_child must not increment
   ========================================================= */
BOOLEAN test_add_child256_collision()
{
    TEST_START("add_child256: collision handling");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    ART_NODE* first = t_alloc_dummy_child(NODE256);
    ART_NODE* second = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n && first && second, "3-pre: alloc inputs");

    n->base.type = NODE256;
    UCHAR c = 123;

    // Pre-occupy slot
    n->children[c] = first;
    n->base.num_of_child = 1;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256(n, NULL, c, second);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.1: occupied slot must return COLLISION");
    TEST_ASSERT(n->base.num_of_child == 1, "3.2: num_of_child unchanged on collision");
    TEST_ASSERT(n->children[c] == first, "3.3: child pointer unchanged");

    t_free(second);
    // free pre-existing
    t_free(first);
    t_free(n);

    TEST_END("add_child256: collision handling");
    return TRUE;
}

/* =========================================================
   Test 4: Node full (num_of_child >= 256)
   Case:
     - Return STATUS_INSUFFICIENT_RESOURCES and do not write
   ========================================================= */
BOOLEAN test_add_child256_full()
{
    TEST_START("add_child256: node full");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    ART_NODE* child = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n && child, "4-pre: alloc inputs");

    // Mark full; children entries may be empty but counter dictates capacity
    n->base.type = NODE256;
    n->base.num_of_child = 256;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256(n, NULL, 42, child);
#pragma warning(pop)

    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "4.1: full node must be rejected");
    TEST_ASSERT(n->children[42] == NULL, "4.2: must not write into children");
    TEST_ASSERT(n->base.num_of_child == 256, "4.3: count unchanged");

    t_free(child);
    t_free(n);

    TEST_END("add_child256: node full");
    return TRUE;
}

/* =========================================================
   Test 5: Success path (single insert)
   Case:
     - Valid NODE256, empty slot , STATUS_SUCCESS
     - num_of_child increments, pointer set
   ========================================================= */
BOOLEAN test_add_child256_success_single()
{
    TEST_START("add_child256: success single insert");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    ART_NODE* child = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n && child, "5-pre: alloc inputs");
    n->base.type = NODE256;

    UCHAR c = 0x00;
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256(n, NULL, c, child);
#pragma warning(pop)

    TEST_ASSERT(NT_SUCCESS(st), "5.1: must succeed on empty slot");
    TEST_ASSERT(n->base.num_of_child == 1, "5.2: num_of_child increments");
    TEST_ASSERT(n->children[c] == child, "5.3: pointer stored");

    // Re-insert same slot, should collide
    ART_NODE* child2 = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(child2 != NULL, "5.4-pre: alloc second child");
#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child256(n, NULL, c, child2);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "5.4: collision on same index");
    TEST_ASSERT(n->base.num_of_child == 1, "5.5: count unchanged after collision");

    t_free(child2);
    t_free(child);
    t_free(n);

    TEST_END("add_child256: success single insert");
    return TRUE;
}

/* =========================================================
   Test 6: Boundary indices (0 and 255)
   Case:
     - Insert at 0 and 255; both succeed; pointers placed correctly.
   ========================================================= */
BOOLEAN test_add_child256_boundaries()
{
    TEST_START("add_child256: boundary indices");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    ART_NODE* c0 = t_alloc_dummy_child(NODE256);
    ART_NODE* c255 = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n && c0 && c255, "6-pre: alloc inputs");
    n->base.type = NODE256;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = add_child256(n, NULL, 0, c0);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "6.1: index 0 ok");
    TEST_ASSERT(n->base.num_of_child == 1, "6.2: count=1");
    TEST_ASSERT(n->children[0] == c0, "6.3: stored at 0");

#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child256(n, NULL, 255, c255);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "6.4: index 255 ok");
    TEST_ASSERT(n->base.num_of_child == 2, "6.5: count=2");
    TEST_ASSERT(n->children[255] == c255, "6.6: stored at 255");

    t_free(c255);
    t_free(c0);
    t_free(n);

    TEST_END("add_child256: boundary indices");
    return TRUE;
}

/* =========================================================
   Test 7: Multiple inserts (different slots)
   Case:
     - Insert several children; ensure count increments and slots are set.
   ========================================================= */
BOOLEAN test_add_child256_multiple_inserts()
{
    TEST_START("add_child256: multiple inserts");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256(); TEST_ASSERT(n, "7-pre: node alloc");
    n->base.type = NODE256;

    const UCHAR idxs[] = { 3, 7, 19, 101, 200 };
    ART_NODE* kids[RTL_NUMBER_OF(idxs)] = { 0 };

    for (ULONG i = 0; i < RTL_NUMBER_OF(idxs); ++i) {
        kids[i] = t_alloc_dummy_child(NODE256); TEST_ASSERT(kids[i], "7-pre: child alloc");
#pragma warning(push)
#pragma warning(disable: 6387)
        NTSTATUS st = add_child256(n, NULL, idxs[i], kids[i]);
#pragma warning(pop)
        TEST_ASSERT(NT_SUCCESS(st), "7.x: insert must succeed");
        TEST_ASSERT(n->children[idxs[i]] == kids[i], "7.x: pointer stored");
        TEST_ASSERT(n->base.num_of_child == (USHORT)(i + 1), "7.x: count tracks inserts");
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(idxs); ++i) t_free(kids[i]);
    t_free(n);

    TEST_END("add_child256: multiple inserts");
    return TRUE;
}

/* =========================================================
   Test 8: No alloc/free side-effects
   ========================================================= */
BOOLEAN test_add_child256_no_allocfree_sideeffects()
{
    TEST_START("add_child256: no alloc/free side-effects");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    ART_NODE* ch = t_alloc_dummy_child(NODE256);
    TEST_ASSERT(n && ch, "8-pre: alloc inputs");
    n->base.type = NODE256;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

#pragma warning(push)
#pragma warning(disable: 6387)
    (void)add_child256(n, NULL, 11, ch);
#pragma warning(pop)

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.1: counters unchanged");

    // detach & free
    n->children[11] = NULL;
    t_free(ch);
    t_free(n);

    TEST_END("add_child256: no alloc/free side-effects");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_add_child256_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting add_child256() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_add_child256_guards())                    all_passed = FALSE;
    if (!test_add_child256_wrong_type())                all_passed = FALSE;
    if (!test_add_child256_collision())                 all_passed = FALSE;
    if (!test_add_child256_full())                      all_passed = FALSE;
    if (!test_add_child256_success_single())            all_passed = FALSE;
    if (!test_add_child256_boundaries())                all_passed = FALSE;
    if (!test_add_child256_multiple_inserts())          all_passed = FALSE;
    if (!test_add_child256_no_allocfree_sideeffects())  all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL add_child256() TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME add_child256() TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
