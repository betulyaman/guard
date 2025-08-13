#include "test_art.h"

// Function under test
STATIC NTSTATUS add_child4(_Inout_ ART_NODE4* node,
    _Inout_ ART_NODE** ref,
    _In_ UCHAR c,
    _In_ PVOID child);

/* =========================================================
   Test 1: Guard checks
   ========================================================= */
BOOLEAN test_add_child4_guards()
{
    TEST_START("add_child4: guards");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "1-pre: child alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    NTSTATUS st;
#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child4(NULL, NULL, 0, ch);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node must be rejected");

#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child4(n, NULL, 1, ch);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref must be rejected");

#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child4(n, (ART_NODE**)&n, 2, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: NULL child must be rejected");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no internal alloc/free on guards");

    t_free(ch);
    t_free(n);

    TEST_END("add_child4: guards");
    return TRUE;
}

/* =========================================================
   Test 2: Wrong type
   ========================================================= */
BOOLEAN test_add_child4_wrong_type()
{
    TEST_START("add_child4: wrong type");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "2-pre: node4 alloc");

    n->base.type = NODE16; // corrupt

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "2-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child4(n, &ref, 10, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: non-NODE4 must be rejected");
    TEST_ASSERT(ref == (ART_NODE*)n, "2.2: ref unchanged on reject");
    TEST_ASSERT(n->base.num_of_child == 0, "2.3: count unchanged");

    t_free(ch);
    n->base.type = NODE4;
    t_free(n);

    TEST_END("add_child4: wrong type");
    return TRUE;
}

/* =========================================================
   Test 3: Duplicate key detection (begin/middle/end)
   ========================================================= */
BOOLEAN test_add_child4_duplicate_key()
{
    TEST_START("add_child4: duplicate key");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "3-pre: node4 alloc");

    TEST_ASSERT(t_seed_node4_sorted(n, 3, 0x20), "3-pre: seed 3 keys (0x20..0x22)");

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "3-pre: new child alloc");
    ART_NODE* ref = (ART_NODE*)n;

    // duplicate at beginning (0x20)
    NTSTATUS st = add_child4(n, &ref, 0x20, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.1: duplicate at beginning");

    // middle (0x21)
    st = add_child4(n, &ref, 0x21, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.2: duplicate in middle");

    // end (0x22)
    st = add_child4(n, &ref, 0x22, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.3: duplicate at end");

    t_free(ch);
    t_free_children4(n);
    t_free(n);

    TEST_END("add_child4: duplicate key");
    return TRUE;
}

/* =========================================================
   Test 4: Direct insert — beginning (shift right)
   ========================================================= */
BOOLEAN test_add_child4_insert_begin()
{
    TEST_START("add_child4: direct insert at beginning");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "4-pre: node4 alloc");

    TEST_ASSERT(t_seed_node4_sorted(n, 3, 0x30), "4-pre: seed 3 keys (0x30..0x32)");

    ART_NODE* newCh = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newCh != NULL, "4-pre: new child");

    ART_NODE* old0 = n->children[0];
    ART_NODE* old1 = n->children[1];
    ART_NODE* old2 = n->children[2];

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child4(n, &ref, 0x20, newCh);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: insert should succeed");
    TEST_ASSERT(n->base.num_of_child == 4, "4.2: count=4");

    TEST_ASSERT(n->keys[0] == 0x20 && n->keys[1] == 0x30 &&
        n->keys[2] == 0x31 && n->keys[3] == 0x32, "4.3: sorted with new at front");

    TEST_ASSERT(n->children[0] == newCh && n->children[1] == old0 &&
        n->children[2] == old1 && n->children[3] == old2, "4.4: children shifted");

    TEST_ASSERT(ref == (ART_NODE*)n, "4.5: ref unchanged (direct path)");

    // cleanup
    t_free(newCh);
    n->children[1] = n->children[2] = n->children[3] = NULL;
    t_free(old0); t_free(old1); t_free(old2);
    t_free(n);

    TEST_END("add_child4: direct insert at beginning");
    return TRUE;
}

/* =========================================================
   Test 5: Direct insert — middle (shift tail)
   ========================================================= */
BOOLEAN test_add_child4_insert_middle()
{
    TEST_START("add_child4: direct insert in middle");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "5-pre: node4 alloc");

    // Arrange desired keys: 0x10, 0x30, 0x50
    TEST_ASSERT(t_seed_node4_sorted(n, 3, 0x10), "5-pre: seed 3");
    n->keys[0] = 0x10; n->keys[1] = 0x30; n->keys[2] = 0x50;

    ART_NODE* newCh = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(newCh != NULL, "5-pre: new child");

    ART_NODE* c0 = n->children[0], * c1 = n->children[1], * c2 = n->children[2];
    ART_NODE* ref = (ART_NODE*)n;

    NTSTATUS st = add_child4(n, &ref, 0x40, newCh); // between 0x30 and 0x50
    TEST_ASSERT(NT_SUCCESS(st), "5.1: insert middle succeed");
    TEST_ASSERT(n->base.num_of_child == 4, "5.2: count=4");

    TEST_ASSERT(n->keys[0] == 0x10 && n->keys[1] == 0x30 &&
        n->keys[2] == 0x40 && n->keys[3] == 0x50, "5.3: sorted keys");

    TEST_ASSERT(n->children[0] == c0 && n->children[1] == c1 &&
        n->children[2] == newCh && n->children[3] == c2, "5.4: children shifted");

    TEST_ASSERT(ref == (ART_NODE*)n, "5.5: ref unchanged");

    // cleanup
    t_free(newCh);
    n->children[0] = n->children[1] = n->children[3] = NULL;
    t_free(c0); t_free(c1); t_free(c2);
    t_free(n);

    TEST_END("add_child4: direct insert in middle");
    return TRUE;
}

/* =========================================================
   Test 6: Direct insert — end (no shift)
   ========================================================= */
BOOLEAN test_add_child4_insert_end()
{
    TEST_START("add_child4: direct insert at end");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "6-pre: node4 alloc");

    TEST_ASSERT(t_seed_node4_sorted(n, 3, 0x10), "6-pre: seed 3");
    n->keys[0] = 0x10; n->keys[1] = 0x20; n->keys[2] = 0x30;

    ART_NODE* newCh = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newCh != NULL, "6-pre: new child");

    ART_NODE* c0 = n->children[0], * c1 = n->children[1], * c2 = n->children[2];
    ART_NODE* ref = (ART_NODE*)n;

    USHORT before = n->base.num_of_child;
    NTSTATUS st = add_child4(n, &ref, 0x40, newCh);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: insert end succeed");
    TEST_ASSERT(n->base.num_of_child == (USHORT)(before + 1), "6.2: count incremented");
    TEST_ASSERT(n->base.num_of_child == 4, "6.2: count=4");

    TEST_ASSERT(n->keys[0] == 0x10 && n->keys[1] == 0x20 &&
        n->keys[2] == 0x30 && n->keys[3] == 0x40, "6.3: sorted");

    TEST_ASSERT(n->children[0] == c0 && n->children[1] == c1 &&
        n->children[2] == c2 && n->children[3] == newCh, "6.4: children correct");

    TEST_ASSERT(ref == (ART_NODE*)n, "6.5: ref unchanged");

    // cleanup
    t_free(newCh);
    n->children[0] = n->children[1] = n->children[2] = NULL;
    t_free(c0); t_free(c1); t_free(c2);
    t_free(n);

    TEST_END("add_child4: direct insert at end");
    return TRUE;
}

/* =========================================================
   Test 7: Multiple inserts keep array sorted
   ========================================================= */
BOOLEAN test_add_child4_multiple_inserts_sorted()
{
    TEST_START("add_child4: multiple inserts sorted");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "7-pre: node4 alloc");

    // start with two: 0x20, 0x40
    TEST_ASSERT(t_seed_node4_sorted(n, 2, 0x20), "7-pre: seed 2");
    n->keys[0] = 0x20; n->keys[1] = 0x40;

    ART_NODE* ref = (ART_NODE*)n;

    UCHAR to_add[] = { 0x10, 0x30 };
    ART_NODE* chA = t_alloc_dummy_child(NODE4);
    ART_NODE* chB = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(chA && chB, "7-pre: child allocs");

    NTSTATUS st = add_child4(n, &ref, to_add[0], chA);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: insert 0x10");
    st = add_child4(n, &ref, to_add[1], chB);
    TEST_ASSERT(NT_SUCCESS(st), "7.2: insert 0x30");

    // Expect keys: 0x10, 0x20, 0x30, 0x40
    TEST_ASSERT(n->base.num_of_child == 4, "7.3: count=4");
    TEST_ASSERT(n->keys[0] == 0x10 && n->keys[1] == 0x20 &&
        n->keys[2] == 0x30 && n->keys[3] == 0x40, "7.4: sorted final");

    // cleanup: detach children to free safely
    t_free_children4(n);
    t_free(n);

    TEST_END("add_child4: multiple inserts sorted");
    return TRUE;
}

/* =========================================================
   Test 8: No internal alloc/free on direct insert path
   ========================================================= */
BOOLEAN test_add_child4_no_allocfree_direct()
{
    TEST_START("add_child4: no alloc/free on direct path");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "8-pre: node4 alloc");
    TEST_ASSERT(t_seed_node4_sorted(n, 1, 0x10), "8-pre: seed 1");

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "8-pre: child alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child4(n, &ref, 0x20, ch);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: insert succeed");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.2: no internal alloc/free");

    // cleanup
    t_free_children4(n);
    t_free(n);

    TEST_END("add_child4: no alloc/free on direct path");
    return TRUE;
}

/* =========================================================
   Test 9: Full node , expand to NODE16 (happy path)
   ========================================================= */
BOOLEAN test_add_child4_expand_to_16_success()
{
    TEST_START("add_child4: expand to NODE16 (success)");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "9-pre: node4 alloc");

    TEST_ASSERT(t_seed_node4_sorted(n, 4, 0x10), "9-pre: seed 4");
    n->keys[0] = 0x10; n->keys[1] = 0x20; n->keys[2] = 0x30; n->keys[3] = 0x40;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "9-pre: new child");

    ULONG frees_before = g_free_call_count;

    // Insert a new smallest key: 0x05 , triggers expansion
    NTSTATUS st = add_child4(n, &ref, 0x05, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: expansion must succeed");
    TEST_ASSERT(ref != (ART_NODE*)n, "9.2: ref updated to new NODE16");

    ART_NODE16* n16 = (ART_NODE16*)ref;
    TEST_ASSERT(n16->base.type == NODE16, "9.3: new node type is NODE16");

    // old node freed (>= +1 güvenli)
    TEST_ASSERT(g_free_call_count >= frees_before + 1, "9.4: old NODE4 freed (>= +1)");

    TEST_ASSERT(n16->keys[0] == 0x10 && n16->keys[1] == 0x20 &&
        n16->keys[2] == 0x30 && n16->keys[3] == 0x40, "9.5: keys copied to NODE16");

    BOOLEAN foundNew = FALSE;
    for (USHORT i = 0; i < n16->base.num_of_child; i++) {
        if (n16->keys[i] == 0x05) {
            TEST_ASSERT(n16->children[i] == newChild, "9.6: new child stored at matching key");
            foundNew = TRUE;
            break;
        }
    }
    TEST_ASSERT(foundNew, "9.7: new key present in NODE16");

    t_free_children16(n16);
    t_free(n16);

    TEST_END("add_child4: expand to NODE16 (success)");
    return TRUE;
}

/* =========================================================
   Test 9b: Expand success — count check
   ========================================================= */
BOOLEAN test_add_child4_expand_to_16_count_check()
{
    TEST_START("add_child4: expand to NODE16 (count check)");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "9b-pre: node4 alloc");

    // Slots: 0x10,0x20,0x30,0x40
    TEST_ASSERT(t_seed_node4_sorted(n, 4, 0x10), "9b-pre: seed 4");
    n->keys[0] = 0x10; n->keys[1] = 0x20; n->keys[2] = 0x30; n->keys[3] = 0x40;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "9b-pre: new child");

    NTSTATUS st = add_child4(n, &ref, 0x05 /* new minimum */, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "9b.1: expansion must succeed");
    TEST_ASSERT(ref && ((ART_NODE*)ref)->type == NODE16, "9b.2: ref points to NODE16");

    ART_NODE16* n16 = (ART_NODE16*)ref;
    TEST_ASSERT(n16->base.num_of_child == 5, "9b.3: new_node->num_of_child must be 5");

    // cleanup
    t_free_children16(n16);
    t_free(n16);

    TEST_END("add_child4: expand to NODE16 (count check)");
    return TRUE;
}

/* =========================================================
   Test 10: Full node , expand to NODE16 but art_create_node fails
   ========================================================= */
BOOLEAN test_add_child4_expand_alloc_failure()
{
    TEST_START("add_child4: expand , art_create_node alloc failure");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "10-pre: node4 alloc");

    TEST_ASSERT(t_seed_node4_sorted(n, 4, 0x40), "10-pre: seed 4");

    ART_NODE* ref = (ART_NODE*)n;

    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "10-pre: new child alloc");

    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, g_alloc_call_count);

    ULONG frees_before = g_free_call_count;
    NTSTATUS st = add_child4(n, &ref, 0x10 /* new key */, newChild);

    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "10.1: must return INSUFFICIENT_RESOURCES");
    TEST_ASSERT(ref == (ART_NODE*)n, "10.2: ref must remain the old NODE4");
    TEST_ASSERT(g_free_call_count == frees_before, "10.3: no frees performed on early alloc failure");

    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0);

    // cleanup
    t_free(newChild);
    t_free_children4(n);
    t_free(n);

    TEST_END("add_child4: expand , art_create_node alloc failure");
    return TRUE;
}

/* =========================================================
   NEW 11: Direct insert into empty node
   ========================================================= */
BOOLEAN test_add_child4_insert_into_empty()
{
    TEST_START("add_child4: direct insert into empty");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n, "11-pre: node4 alloc");
    n->base.num_of_child = 0;

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch, "11-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child4(n, &ref, 0x33, ch);
    TEST_ASSERT(NT_SUCCESS(st), "11.1: should insert into empty");
    TEST_ASSERT(n->base.num_of_child == 1, "11.2: count=1");
    TEST_ASSERT(n->keys[0] == 0x33, "11.3: key placed at 0");
    TEST_ASSERT(n->children[0] == ch, "11.4: child pointer placed");
    TEST_ASSERT(ref == (ART_NODE*)n, "11.5: ref unchanged");

    // cleanup
    n->children[0] = NULL;
    t_free(ch);
    t_free(n);

    TEST_END("add_child4: direct insert into empty");
    return TRUE;
}

/* =========================================================
   NEW 12: Corrupted count (>4) — expand path clamps safely (strict=0)
           or errors out (strict=1)
   ========================================================= */
BOOLEAN test_add_child4_expand_clamp_or_strict()
{
    TEST_START("add_child4: expand with corrupted count");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n, "12-pre: node4 alloc");

    // Prepare 4 valid entries
    n->keys[0] = 0x10; n->children[0] = t_alloc_dummy_child(NODE4);
    n->keys[1] = 0x20; n->children[1] = t_alloc_dummy_child(NODE4);
    n->keys[2] = 0x30; n->children[2] = t_alloc_dummy_child(NODE4);
    n->keys[3] = 0x40; n->children[3] = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(n->children[0] && n->children[1] && n->children[2] && n->children[3], "12-pre: child allocs");

    n->base.type = NODE4;
    n->base.num_of_child = 7; // corrupted count -> expand branch

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild, "12-pre: new child");

    NTSTATUS st = add_child4(n, &ref, 0x05, newChild);

#if ART_STRICT_NODE4_VERIFY
    TEST_ASSERT(st == STATUS_DATA_ERROR, "12.1(strict): expect DATA_ERROR");
    // cleanup original
    for (int i = 0; i < 4; i++) { t_free(n->children[i]); n->children[i] = NULL; }
    t_free(newChild);
    t_free(n);
#else
    TEST_ASSERT(NT_SUCCESS(st), "12.1: expect success with clamping");
    TEST_ASSERT(ref && ((ART_NODE*)ref)->type == NODE16, "12.2: expanded to NODE16");
    ART_NODE16* n16 = (ART_NODE16*)ref;
    TEST_ASSERT(n16->base.num_of_child == 5, "12.3: 4 survivors + 1 new = 5");

    // cleanup
    t_free_children16(n16);
    t_free(n16);
#endif

    TEST_END("add_child4: expand with corrupted count");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_add_child4_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting add_child4() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_add_child4_guards())                    all_passed = FALSE; // 1
    if (!test_add_child4_wrong_type())                all_passed = FALSE; // 2
    if (!test_add_child4_duplicate_key())             all_passed = FALSE; // 3
    if (!test_add_child4_insert_begin())              all_passed = FALSE; // 4
    if (!test_add_child4_insert_middle())             all_passed = FALSE; // 5
    if (!test_add_child4_insert_end())                all_passed = FALSE; // 6
    if (!test_add_child4_multiple_inserts_sorted())   all_passed = FALSE; // 7
    if (!test_add_child4_no_allocfree_direct())       all_passed = FALSE; // 8
    if (!test_add_child4_expand_to_16_success())      all_passed = FALSE; // 9
    if (!test_add_child4_expand_to_16_count_check())  all_passed = FALSE; // 9b
    if (!test_add_child4_expand_alloc_failure())      all_passed = FALSE; // 10
    if (!test_add_child4_insert_into_empty())         all_passed = FALSE; // 11
    if (!test_add_child4_expand_clamp_or_strict())    all_passed = FALSE; // 12

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL add_child4() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME add_child4() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}