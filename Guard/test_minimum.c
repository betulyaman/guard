#include "test_art.h"

// Function under test
STATIC ART_LEAF* minimum(CONST ART_NODE* node);

/* =========================================================
   Test 1: NULL input
   Purpose:
     - node == NULL , return NULL
     - No alloc/free inside minimum()
   ========================================================= */
BOOLEAN test_minimum_null_input()
{
    TEST_START("minimum: NULL input");

    reset_mock_state();
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_LEAF* got = minimum(NULL);
    TEST_ASSERT(got == NULL, "1.1: minimum(NULL) must return NULL");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.1: no alloc/free inside");

    LOG_MSG("[INFO] Test 1 completed\n");
    TEST_END("minimum: NULL input");
    return TRUE;
}

/* =========================================================
   Test 2: Leaf fast-path
   Purpose:
     - IS_LEAF(node) , return LEAF_RAW(node)
   ========================================================= */
BOOLEAN test_minimum_leaf_fastpath()
{
    TEST_START("minimum: leaf fast-path");

    reset_mock_state();
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_LEAF* raw = test_alloc_leaf(3, 0x20);
    TEST_ASSERT(raw != NULL, "2-pre: allocate leaf");

    ART_NODE* tagged = SET_LEAF(raw);
    TEST_ASSERT(IS_LEAF(tagged), "2-pre: tagged pointer must be recognized as leaf");

    ART_LEAF* got = minimum(tagged);
    TEST_ASSERT(got == raw, "2.1: minimum on leaf returns same raw leaf");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "2.1: no alloc/free inside");

    test_free_leaf(raw);

    LOG_MSG("[INFO] Test 2 completed\n");
    TEST_END("minimum: leaf fast-path");
    return TRUE;
}

/* =========================================================
   Test 3: Invalid node type and zero-children guard
   Purpose:
     - (3.1) invalid type , NULL
     - (3.2) valid types with num_of_child==0 , NULL
   ========================================================= */
BOOLEAN test_minimum_invalid_and_empty()
{
    TEST_START("minimum: invalid type & empty nodes");

    // (3.1) invalid type
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.1-pre: base alloc");
        n->type = (NODE_TYPE)0; // invalid (must be NODE4..NODE256 or leaf)
        n->num_of_child = 1;
        ART_LEAF* got = minimum(n);
        TEST_ASSERT(got == NULL, "3.1: invalid type must return NULL");
        test_free_node_all(n);
    }

    // (3.2a) NODE4 with 0 children
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "3.2a-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 0;
        ART_LEAF* got = minimum(&n4->base);
        TEST_ASSERT(got == NULL, "3.2a: NODE4 with 0 children , NULL");
        test_free_node_all(n4);
    }

    // (3.2b) NODE16 with 0 children
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "3.2b-pre: node16 alloc");
        n16->base.type = NODE16;
        n16->base.num_of_child = 0;
        ART_LEAF* got = minimum(&n16->base);
        TEST_ASSERT(got == NULL, "3.2b: NODE16 with 0 children , NULL");
        test_free_node_all(n16);
    }

    // (3.2c) NODE48 with 0 children (all maps zero)
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "3.2c-pre: node48 alloc");
        n48->base.type = NODE48;
        n48->base.num_of_child = 0;
        ART_LEAF* got = minimum(&n48->base);
        TEST_ASSERT(got == NULL, "3.2c: NODE48 with 0 children , NULL");
        test_free_node_all(n48);
    }

    // (3.2d) NODE256 with 0 children
    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "3.2d-pre: node256 alloc");
        n256->base.type = NODE256;
        n256->base.num_of_child = 0;
        ART_LEAF* got = minimum(&n256->base);
        TEST_ASSERT(got == NULL, "3.2d: NODE256 with 0 children , NULL");
        test_free_node_all(n256);
    }

    LOG_MSG("[INFO] Test 3 completed\n");
    TEST_END("minimum: invalid type & empty nodes");
    return TRUE;
}

/* =========================================================
   Test 4: NODE4 traversal (first non-NULL child)
   Purpose:
     - First non-NULL child is recursed
   Sub-cases:
     (4.1) children[0] present , picked
     (4.2) children[0]==NULL, children[1] present , picked
   ========================================================= */
BOOLEAN test_minimum_node4_traversal()
{
    TEST_START("minimum: NODE4 traversal");

    // (4.1)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.1-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 1;

        ART_LEAF* lf = test_alloc_leaf(2, 0x10); TEST_ASSERT(lf, "4.1-pre: leaf alloc");
        n4->children[0] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n4->base);
        TEST_ASSERT(got == lf, "4.1: must return first child's leaf");

        test_free_leaf(lf);
        test_free_node_all(n4);
    }

    // (4.2)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.2-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 2;

        ART_LEAF* lf = test_alloc_leaf(3, 0x20); TEST_ASSERT(lf, "4.2-pre: leaf alloc");
        n4->children[0] = NULL;
        n4->children[1] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n4->base);
        TEST_ASSERT(got == lf, "4.2: must skip NULL and pick first non-NULL");

        test_free_leaf(lf);
        test_free_node_all(n4);
    }

    LOG_MSG("[INFO] Test 4 completed\n");
    TEST_END("minimum: NODE4 traversal");
    return TRUE;
}

/* =========================================================
   Test 5: NODE16 traversal (first non-NULL child)
   ========================================================= */
BOOLEAN test_minimum_node16_traversal()
{
    TEST_START("minimum: NODE16 traversal");

    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "5-pre: node16 alloc");
        n16->base.type = NODE16;
        n16->base.num_of_child = 3;

        // children[0]==NULL, children[1]==NULL, children[2]==leaf
        ART_LEAF* lf = test_alloc_leaf(4, 0x30); TEST_ASSERT(lf, "5-pre: leaf alloc");
        n16->children[2] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n16->base);
        TEST_ASSERT(got == lf, "5.1: should pick index 2 as first non-NULL");

        test_free_leaf(lf);
        test_free_node_all(n16);
    }

    LOG_MSG("[INFO] Test 5 completed\n");
    TEST_END("minimum: NODE16 traversal");
    return TRUE;
}

/* =========================================================
   Test 6: NODE48 traversal via child_index mapping
   Purpose:
     - Find first non-zero mapping i where children[child_index[i]-1] exists
   Sub-cases:
     (6.1) first hit at small i
     (6.2) earlier indices map to empty slots; actual child later
   ========================================================= */
BOOLEAN test_minimum_node48_traversal()
{
    TEST_START("minimum: NODE48 traversal");

    // (6.1)
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "6.1-pre: node48 alloc");
        n48->base.type = NODE48;
        n48->base.num_of_child = 1;

        ART_LEAF* lf = test_alloc_leaf(5, 0x40); TEST_ASSERT(lf, "6.1-pre: leaf alloc");

        // map byte 3 -> slot 0 (index=1)
        n48->child_index[3] = 1; // 1-based
        n48->children[0] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n48->base);
        TEST_ASSERT(got == lf, "6.1: first non-zero mapping should be chosen");

        test_free_leaf(lf);
        test_free_node_all(n48);
    }

    // (6.2)
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "6.2-pre: node48 alloc");
        n48->base.type = NODE48;
        n48->base.num_of_child = 1;

        // earlier maps point to empty slots
        n48->child_index[1] = 0; 
        n48->child_index[2] = 0; 

        // valid mapping later
        ART_LEAF* lf = test_alloc_leaf(6, 0x50); TEST_ASSERT(lf, "6.2-pre: leaf alloc");
        n48->child_index[10] = 1; // -> slot 0
        n48->children[0] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n48->base);
        TEST_ASSERT(got == lf, "6.2: must skip unmapped/NULL and return first valid child");

        test_free_leaf(lf);
        test_free_node_all(n48);
    }

    LOG_MSG("[INFO] Test 6 completed\n");
    TEST_END("minimum: NODE48 traversal");
    return TRUE;
}

/* =========================================================
   Test 7: NODE256 traversal (first non-NULL child)
   ========================================================= */
BOOLEAN test_minimum_node256_traversal()
{
    TEST_START("minimum: NODE256 traversal");

    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "7-pre: node256 alloc");
        n256->base.type = NODE256;
        n256->base.num_of_child = 4;

        // place leaf at a higher index; earlier slots NULL
        ART_LEAF* lf = test_alloc_leaf(7, 0x60); TEST_ASSERT(lf, "7-pre: leaf alloc");
        n256->children[123] = SET_LEAF(lf);

        ART_LEAF* got = minimum(&n256->base);
        TEST_ASSERT(got == lf, "7.1: must return first non-NULL child");

        test_free_leaf(lf);
        test_free_node_all(n256);
    }

    LOG_MSG("[INFO] Test 7 completed\n");
    TEST_END("minimum: NODE256 traversal");
    return TRUE;
}

/* =========================================================
   Test 8: Multi-level recursion
   Purpose:
     NODE4 -> NODE16 -> NODE48 -> NODE256 -> LEAF
     The minimum must traverse down to the leftmost reachable leaf.
   ========================================================= */
BOOLEAN test_minimum_multilevel_recursion()
{
    TEST_START("minimum: multi-level recursion");

    reset_mock_state();

    // Deep leaf
    ART_LEAF* deep_leaf = test_alloc_leaf(8, 0x70);
    TEST_ASSERT(deep_leaf, "8-pre: deep leaf alloc");

    // NODE256 with child at index 0 pointing to leaf
    ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "8-pre: node256 alloc");
    n256->base.type = NODE256; n256->base.num_of_child = 1;
    n256->children[0] = SET_LEAF(deep_leaf);

    // NODE48 mapping smallest byte to slot 0 -> n256
    ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "8-pre: node48 alloc");
    n48->base.type = NODE48; n48->base.num_of_child = 1;
    n48->child_index[0] = 1; // 1-based
    n48->children[0] = (ART_NODE*)n256; // not leaf here, direct node

    // NODE16 first child -> n48
    ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "8-pre: node16 alloc");
    n16->base.type = NODE16; n16->base.num_of_child = 1;
    n16->children[0] = (ART_NODE*)n48;

    // NODE4 first child -> n16
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "8-pre: node4 alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 1;
    n4->children[0] = (ART_NODE*)n16;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* got = minimum(&n4->base);
    TEST_ASSERT(got == deep_leaf, "8.1: must reach the deepest leftmost leaf");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.1: no alloc/free inside minimum");

    // cleanup (bottom-up)
    test_free_leaf(deep_leaf);
    test_free_node_all(n256);
    test_free_node_all(n48);
    test_free_node_all(n16);
    test_free_node_all(n4);

    LOG_MSG("[INFO] Test 8 completed\n");
    TEST_END("minimum: multi-level recursion");
    return TRUE;
}

/* =========================================================
   Test 9: No alloc/free side-effects (sanity)
   Purpose:
     - Ensure minimum() itself never allocates/frees
   ========================================================= */
BOOLEAN test_minimum_no_allocfree_sideeffects()
{
    TEST_START("minimum: no alloc/free side-effects");

    reset_mock_state();

    // Simple chain: NODE4 -> leaf
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "9-pre: node4 alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 1;
    ART_LEAF* lf = test_alloc_leaf(2, 0x22); TEST_ASSERT(lf, "9-pre: leaf alloc");
    n4->children[0] = SET_LEAF(lf);

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    (void)minimum(&n4->base);
    (void)minimum(&n4->base);
    (void)minimum(&n4->base);

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "9.1: counters unchanged across calls");

    test_free_leaf(lf);
    test_free_node_all(n4);

    LOG_MSG("[INFO] Test 9 completed\n");
    TEST_END("minimum: no alloc/free side-effects");
    return TRUE;
}

BOOLEAN test_minimum_node48_corrupt_mapped_null_returns_null()
{
    TEST_START("minimum: NODE48 mapped, NULL is corruption (returns NULL)");

    reset_mock_state();
    ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "pre: node48 alloc");
    n48->base.type = NODE48;
    n48->base.num_of_child = 1;

    // Kasıtlı korupsiyon: map var ama children NULL
    n48->child_index[7] = 1;   // -> slot 0
    n48->children[0] = NULL;

    ART_LEAF* got = minimum(&n48->base);
    TEST_ASSERT(got == NULL, "mapped NULL child must be treated as corruption");

    test_free_node_all(n48);
    TEST_END("minimum: NODE48 mapped, NULL is corruption (returns NULL)");
    return TRUE;
}


/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_minimum_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting minimum() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_minimum_null_input())              all_passed = FALSE;  // Test 1
    if (!test_minimum_leaf_fastpath())           all_passed = FALSE;  // Test 2
    if (!test_minimum_invalid_and_empty())       all_passed = FALSE;  // Test 3
    if (!test_minimum_node4_traversal())         all_passed = FALSE;  // Test 4
    if (!test_minimum_node16_traversal())        all_passed = FALSE;  // Test 5
    if (!test_minimum_node48_traversal())        all_passed = FALSE;  // Test 6
    if (!test_minimum_node256_traversal())       all_passed = FALSE;  // Test 7
    if (!test_minimum_multilevel_recursion())    all_passed = FALSE;  // Test 8
    if (!test_minimum_no_allocfree_sideeffects())all_passed = FALSE;  // Test 9
    if (!test_minimum_node48_corrupt_mapped_null_returns_null())all_passed = FALSE;  // Test 10

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL minimum() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME minimum() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
