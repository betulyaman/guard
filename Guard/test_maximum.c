#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC ART_LEAF* maximum(CONST ART_NODE* node);

/* =========================================================
   Test 1: NULL input
   Purpose:
     - node == NULL , return NULL
     - No alloc/free inside maximum()
   ========================================================= */
BOOLEAN test_maximum_null_input()
{
    TEST_START("maximum: NULL input");

    reset_mock_state();
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_LEAF* got = maximum(NULL);
    TEST_ASSERT(got == NULL, "1.1: maximum(NULL) must return NULL");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.1: no alloc/free inside");

    TEST_END("maximum: NULL input");
    return TRUE;
}

/* =========================================================
   Test 2: Leaf fast-path
   Purpose:
     - IS_LEAF(node) , return LEAF_RAW(node)
   ========================================================= */
BOOLEAN test_maximum_leaf_fastpath()
{
    TEST_START("maximum: leaf fast-path");

    reset_mock_state();
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_LEAF* raw = test_alloc_leaf(3, 0x10);
    TEST_ASSERT(raw != NULL, "2-pre: allocate leaf");
    ART_NODE* tagged = SET_LEAF(raw);
    TEST_ASSERT(IS_LEAF(tagged), "2-pre: tagged pointer must be recognized as leaf");

    ART_LEAF* got = maximum(tagged);
    TEST_ASSERT(got == raw, "2.1: maximum on leaf returns same raw leaf");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "2.1: no alloc/free inside");

    test_free_leaf(raw);

    TEST_END("maximum: leaf fast-path");
    return TRUE;
}

/* =========================================================
   Test 3: Invalid node type and zero-children guard
   Purpose:
     - (3.1) invalid type , NULL
     - (3.2) valid types with num_of_child==0 , NULL
   ========================================================= */
BOOLEAN test_maximum_invalid_and_empty()
{
    TEST_START("maximum: invalid type & empty nodes");

    // (3.1) invalid type
    reset_mock_state();
    {
        ART_NODE* n = test_alloc_node_base(); TEST_ASSERT(n, "3.1-pre: base alloc");
        n->type = (NODE_TYPE)0; // invalid
        n->num_of_child = 1;
        ART_LEAF* got = maximum(n);
        TEST_ASSERT(got == NULL, "3.1: invalid type must return NULL");
        test_free_node_all(n);
    }

    // (3.2a) NODE4 empty
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "3.2a-pre: node4 alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;
        ART_LEAF* got = maximum(&n4->base);
        TEST_ASSERT(got == NULL, "3.2a: NODE4 with 0 children , NULL");
        test_free_node_all(n4);
    }

    // (3.2b) NODE16 empty
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "3.2b-pre: node16 alloc");
        n16->base.type = NODE16; n16->base.num_of_child = 0;
        ART_LEAF* got = maximum(&n16->base);
        TEST_ASSERT(got == NULL, "3.2b: NODE16 with 0 children , NULL");
        test_free_node_all(n16);
    }

    // (3.2c) NODE48 empty
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "3.2c-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 0;
        ART_LEAF* got = maximum(&n48->base);
        TEST_ASSERT(got == NULL, "3.2c: NODE48 with 0 children , NULL");
        test_free_node_all(n48);
    }

    // (3.2d) NODE256 empty
    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "3.2d-pre: node256 alloc");
        n256->base.type = NODE256; n256->base.num_of_child = 0;
        ART_LEAF* got = maximum(&n256->base);
        TEST_ASSERT(got == NULL, "3.2d: NODE256 with 0 children , NULL");
        test_free_node_all(n256);
    }

    TEST_END("maximum: invalid type & empty nodes");
    return TRUE;
}

/* =========================================================
   Test 4: NODE4 traversal (last non-NULL child)
   Purpose:
     - Iterate indices 3..0, return first non-NULL encountered
   Sub-cases:
     (4.1) only children[3] set
     (4.2) children[3]==NULL, children[2] set
   ========================================================= */
BOOLEAN test_maximum_node4_traversal()
{
    TEST_START("maximum: NODE4 traversal");

    // (4.1) pick index 3
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.1-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 4; // limit = 4 -> 3..0

        ART_LEAF* lf = test_alloc_leaf(2, 0x20); TEST_ASSERT(lf, "4.1-pre: leaf alloc");
        n4->children[3] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n4->base);
        TEST_ASSERT(got == lf, "4.1: must choose highest non-NULL child (index 3)");

        test_free_leaf(lf);
        test_free_node_all(n4);
    }

    // (4.2) index 2 when 3 is NULL
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.2-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 4; // limit = 4 -> 3..0

        ART_LEAF* lf = test_alloc_leaf(3, 0x21); TEST_ASSERT(lf, "4.2-pre: leaf alloc");
        n4->children[3] = NULL;
        n4->children[2] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n4->base);
        TEST_ASSERT(got == lf, "4.2: must skip NULL at 3 and return index 2");

        test_free_leaf(lf);
        test_free_node_all(n4);
    }

    TEST_END("maximum: NODE4 traversal");
    return TRUE;
}

/* =========================================================
   Test 5: NODE16 traversal (last non-NULL child)
   ========================================================= */
BOOLEAN test_maximum_node16_traversal()
{
    TEST_START("maximum: NODE16 traversal");

    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "5-pre: node16 alloc");
        n16->base.type = NODE16;
        n16->base.num_of_child = 16;


        ART_LEAF* lf = test_alloc_leaf(4, 0x30); TEST_ASSERT(lf, "5-pre: leaf alloc");
        n16->children[14] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n16->base);
        TEST_ASSERT(got == lf, "5.1: must return highest non-NULL child (index 14)");

        test_free_leaf(lf);
        test_free_node_all(n16);
    }

    TEST_END("maximum: NODE16 traversal");
    return TRUE;
}


/* =========================================================
   Test 6: NODE48 traversal via child_index (highest byte)
   Purpose:
     - Scan 255..0, first mapped and non-NULL wins
   Sub-cases:
     (6.1) single valid mapping at high byte
     (6.2) higher indices mapped to empty; lower valid later
   ========================================================= */
BOOLEAN test_maximum_node48_traversal()
{
    TEST_START("maximum: NODE48 traversal");

    // (6.1) valid high mapping
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "6.1-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 1;

        ART_LEAF* lf = test_alloc_leaf(5, 0x40); TEST_ASSERT(lf, "6.1-pre: leaf alloc");
        n48->child_index[250] = 1; // -> slot 0
        n48->children[0] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n48->base);
        TEST_ASSERT(got == lf, "6.1: must select highest mapped non-NULL child");

        test_free_leaf(lf);
        test_free_node_all(n48);
    }

    // (6.2) higher mapped but empty; lower valid wins
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "6.2-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 2;

        n48->child_index[254] = 3; // -> slot 2, but leave children[2] NULL
        n48->child_index[200] = 0; // unmapped
        ART_LEAF* lf = test_alloc_leaf(6, 0x50); TEST_ASSERT(lf, "6.2-pre: leaf alloc");
        n48->child_index[180] = 2; // -> slot 1
        n48->children[1] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n48->base);
        TEST_ASSERT(got == lf, "6.2: must skip empty high mapping and pick next valid lower one");

        test_free_leaf(lf);
        test_free_node_all(n48);
    }

    TEST_END("maximum: NODE48 traversal");
    return TRUE;
}

/* =========================================================
   Test 7: NODE256 traversal (last non-NULL child)
   ========================================================= */
BOOLEAN test_maximum_node256_traversal()
{
    TEST_START("maximum: NODE256 traversal");

    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "7-pre: node256 alloc");
        n256->base.type = NODE256; n256->base.num_of_child = 3;

        // Put a leaf at a high index (e.g., 200)
        ART_LEAF* lf = test_alloc_leaf(7, 0x60); TEST_ASSERT(lf, "7-pre: leaf alloc");
        n256->children[200] = SET_LEAF(lf);

        ART_LEAF* got = maximum(&n256->base);
        TEST_ASSERT(got == lf, "7.1: must return the highest non-NULL child");

        test_free_leaf(lf);
        test_free_node_all(n256);
    }

    TEST_END("maximum: NODE256 traversal");
    return TRUE;
}

/* =========================================================
   Test 8: Multi-level recursion (rightmost path)
   Purpose:
     NODE4 -> NODE16 -> NODE48 -> NODE256 -> LEAF
     The maximum must traverse down to the **rightmost** reachable leaf.
   ========================================================= */
BOOLEAN test_maximum_multilevel_recursion()
{
    TEST_START("maximum: multi-level recursion");

    reset_mock_state();

    // Deep leaf
    ART_LEAF* deep_leaf = test_alloc_leaf(8, 0x70);
    TEST_ASSERT(deep_leaf, "8-pre: deep leaf alloc");

    // NODE256 with child at highest index (255)
    ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "8-pre: node256 alloc");
    n256->base.type = NODE256; n256->base.num_of_child = 1;
    n256->children[255] = SET_LEAF(deep_leaf);

    // NODE48 mapping a high byte to slot 0 -> n256
    ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "8-pre: node48 alloc");
    n48->base.type = NODE48; n48->base.num_of_child = 1;
    n48->child_index[255] = 1; // 1-based
    n48->children[0] = (ART_NODE*)n256;

    // NODE16 set a high child -> n48
    ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "8-pre: node16 alloc");
    n16->base.type = NODE16; n16->base.num_of_child = 16;
    n16->children[15] = (ART_NODE*)n48;

    // NODE4 set the last slot -> n16
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "8-pre: node4 alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 4;
    n4->children[3] = (ART_NODE*)n16;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* got = maximum(&n4->base);
    TEST_ASSERT(got == deep_leaf, "8.1: must reach the deepest rightmost leaf");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.1: no alloc/free inside maximum");

    // cleanup
    test_free_leaf(deep_leaf);
    test_free_node_all(n256);
    test_free_node_all(n48);
    test_free_node_all(n16);
    test_free_node_all(n4);

    TEST_END("maximum: multi-level recursion");
    return TRUE;
}

/* =========================================================
   Test 9: No alloc/free side-effects (sanity)
   ========================================================= */
BOOLEAN test_maximum_no_allocfree_sideeffects()
{
    TEST_START("maximum: no alloc/free side-effects");

    reset_mock_state();

    // Simple chain: NODE16 -> leaf at a high slot
    ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "9-pre: node16 alloc");
    n16->base.type = NODE16; n16->base.num_of_child = 16;
    ART_LEAF* lf = test_alloc_leaf(2, 0x22); TEST_ASSERT(lf, "9-pre: leaf alloc");
    n16->children[15] = SET_LEAF(lf);

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    (void)maximum(&n16->base);
    (void)maximum(&n16->base);
    (void)maximum(&n16->base);

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "9.1: counters unchanged across calls");

    test_free_leaf(lf);
    test_free_node_all(n16);

    TEST_END("maximum: no alloc/free side-effects");
    return TRUE;
}

// --- EXTRA: NODE48 corrupt index out-of-range -> NULL ---
BOOLEAN test_maximum_node48_corrupt_index_out_of_range()
{
    TEST_START("maximum: NODE48 corrupt index (>48) -> NULL");
    reset_mock_state();

    ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "pre: node48 alloc");
    n48->base.type = NODE48; n48->base.num_of_child = 1;

    // Geçersiz: 49 (1..48 olmalı)
    n48->child_index[250] = 49;

    ART_LEAF* got = maximum(&n48->base);
    TEST_ASSERT(got == NULL, "corrupt map >48 must yield NULL");

    test_free_node_all(n48);
    TEST_END("maximum: NODE48 corrupt index (>48) -> NULL");
    return TRUE;
}

// --- EXTRA: NODE4 clamp num_of_child > 4 ---
BOOLEAN test_maximum_node4_clamp_over_capacity()
{
    TEST_START("maximum: NODE4 clamp num_of_child>4");
    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "pre: node4 alloc");
    n4->base.type = NODE4;
    n4->base.num_of_child = 9; // kapasite üstü; limit 4 olacak

    // Yüksek tarafta tek yaprak: index 3
    ART_LEAF* lf = test_alloc_leaf(3, 0x23); TEST_ASSERT(lf, "leaf alloc");
    n4->children[3] = SET_LEAF(lf);

    ART_LEAF* got = maximum(&n4->base);
    TEST_ASSERT(got == lf, "must clamp to 4 and pick index 3");

    test_free_leaf(lf);
    test_free_node_all(n4);
    TEST_END("maximum: NODE4 clamp num_of_child>4");
    return TRUE;
}

// --- EXTRA: NODE16 clamp num_of_child > 16 ---
BOOLEAN test_maximum_node16_clamp_over_capacity()
{
    TEST_START("maximum: NODE16 clamp num_of_child>16");
    reset_mock_state();

    ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "pre: node16 alloc");
    n16->base.type = NODE16;
    n16->base.num_of_child = 25; // kapasite üstü; limit 16

    ART_LEAF* lf = test_alloc_leaf(4, 0x24); TEST_ASSERT(lf, "leaf alloc");
    n16->children[15] = SET_LEAF(lf);

    ART_LEAF* got = maximum(&n16->base);
    TEST_ASSERT(got == lf, "must clamp to 16 and pick index 15");

    test_free_leaf(lf);
    test_free_node_all(n16);
    TEST_END("maximum: NODE16 clamp num_of_child>16");
    return TRUE;
}

// --- EXTRA: All descents return NULL -> overall NULL ---
BOOLEAN test_maximum_all_paths_null()
{
    TEST_START("maximum: all descents -> NULL");
    reset_mock_state();

    // NODE4 -> NODE16 -> NODE48 -> NODE256; hiç yaprak yok
    ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "pre: n256");
    n256->base.type = NODE256; n256->base.num_of_child = 1;
    // bütün children[] NULL

    ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48, "pre: n48");
    n48->base.type = NODE48; n48->base.num_of_child = 1;
    n48->child_index[255] = 1;
    n48->children[0] = (ART_NODE*)n256;

    ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16, "pre: n16");
    n16->base.type = NODE16; n16->base.num_of_child = 1;
    n16->children[15] = (ART_NODE*)n48;

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "pre: n4");
    n4->base.type = NODE4; n4->base.num_of_child = 4;
    n4->children[3] = (ART_NODE*)n16;

    ART_LEAF* got = maximum(&n4->base);
    TEST_ASSERT(got == NULL, "no reachable leaf -> NULL");

    test_free_node_all(n4);
    TEST_END("maximum: all descents -> NULL");
    return TRUE;
}

// --- EXTRA: NODE256 highest non-NULL after many NULLs ---
BOOLEAN test_maximum_node256_highest_nonnull_after_nulls()
{
    TEST_START("maximum: NODE256 pick highest non-NULL after NULLs");
    reset_mock_state();

    ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256, "pre: n256");
    n256->base.type = NODE256; n256->base.num_of_child = 2;

    // 255 NULL, 240 leaf
    ART_LEAF* lf = test_alloc_leaf(5, 0x25); TEST_ASSERT(lf, "leaf alloc");
    n256->children[240] = SET_LEAF(lf);

    ART_LEAF* got = maximum(&n256->base);
    TEST_ASSERT(got == lf, "must choose highest non-NULL slot (240)");

    test_free_leaf(lf);
    test_free_node_all(n256);
    TEST_END("maximum: NODE256 pick highest non-NULL after NULLs");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_maximum_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting maximum() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_maximum_null_input())                 all_passed = FALSE;  // 1
    if (!test_maximum_leaf_fastpath())              all_passed = FALSE;  // 2
    if (!test_maximum_invalid_and_empty())          all_passed = FALSE;  // 3
    if (!test_maximum_node4_traversal())            all_passed = FALSE;  // 4
    if (!test_maximum_node16_traversal())           all_passed = FALSE;  // 5
    if (!test_maximum_node48_traversal())           all_passed = FALSE;  // 6
    if (!test_maximum_node256_traversal())          all_passed = FALSE;  // 7
    if (!test_maximum_multilevel_recursion())       all_passed = FALSE;  // 8
    if (!test_maximum_no_allocfree_sideeffects())   all_passed = FALSE;  // 9
    if (!test_maximum_node48_corrupt_index_out_of_range()) all_passed = FALSE;
    if (!test_maximum_node4_clamp_over_capacity())         all_passed = FALSE;
    if (!test_maximum_node16_clamp_over_capacity())        all_passed = FALSE;
    if (!test_maximum_all_paths_null())                    all_passed = FALSE;
    if (!test_maximum_node256_highest_nonnull_after_nulls()) all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL maximum() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME maximum() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif