#include "test_art.h"

// Function under test
STATIC NTSTATUS add_child16(_Inout_ ART_NODE16* node,
    _Inout_ ART_NODE** ref,
    _In_ UCHAR c,
    _In_ PVOID child);


/* =========================================================
   Test 1: Guard checks
   Covers:
     (1.1) node == NULL  , STATUS_INVALID_PARAMETER
     (1.2) ref  == NULL  , STATUS_INVALID_PARAMETER
     (1.3) child== NULL  , STATUS_INVALID_PARAMETER
   Also: no alloc/free side-effects inside the function.
   ========================================================= */
BOOLEAN test_add_child16_guards()
{
    TEST_START("add_child16: guards");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "1-pre: child alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st;
    st = add_child16(NULL, NULL, 0, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node must be rejected");

    st = add_child16(n, NULL, 1, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref must be rejected");

    st = add_child16(n, (ART_NODE**)&n, 2, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: NULL child must be rejected");
#pragma warning(pop)

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no internal alloc/free on guards");

    t_free(ch);
    t_free(n);

    TEST_END("add_child16: guards");
    return TRUE;
}

/* =========================================================
   Test 2: Wrong node type
   Case: node->base.type != NODE16 , STATUS_INVALID_PARAMETER
   ========================================================= */
BOOLEAN test_add_child16_wrong_type()
{
    TEST_START("add_child16: wrong type");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "2-pre: alloc node16");
    n->base.type = NODE4; // corrupt type

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "2-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child16(n, &ref, 10, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: non-NODE16 must be rejected");
    TEST_ASSERT(ref == (ART_NODE*)n, "2.2: ref unchanged on reject");
    TEST_ASSERT(n->base.num_of_child == 0, "2.3: count unchanged");

    t_free(ch);
    // restore type to allow safe free
    n->base.type = NODE16;
    t_free(n);

    TEST_END("add_child16: wrong type");
    return TRUE;
}

/* =========================================================
   Test 3: Duplicate key detection
   Cases: duplicate at beginning / middle / end , COLLISION
   ========================================================= */
BOOLEAN test_add_child16_duplicate_key()
{
    TEST_START("add_child16: duplicate key");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "3-pre: alloc node");

    TEST_ASSERT(t_seed_node16_sorted(n, 5, 0x20), "3-pre: seed 5 sorted keys (0x20..0x24)");

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "3-pre: new child alloc");

    ART_NODE* ref = (ART_NODE*)n;

    // duplicate at beginning (0x20)
    NTSTATUS st = add_child16(n, &ref, 0x20, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.1: duplicate at beginning collides");
    TEST_ASSERT(n->base.num_of_child == 5, "3.1: count unchanged");
    TEST_ASSERT(ref == (ART_NODE*)n, "3.1: ref unchanged");

    // duplicate in middle (0x22)
    st = add_child16(n, &ref, 0x22, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.2: duplicate in middle collides");

    // duplicate at end (0x24)
    st = add_child16(n, &ref, 0x24, ch);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.3: duplicate at end collides");

    t_free(ch);
    t_free_children16(n);
    t_free(n);

    TEST_END("add_child16: duplicate key");
    return TRUE;
}

/* =========================================================
   Test 4: Direct insert — insertion at beginning (shift right)
   Verifies:
     - sorted order
     - children pointers shifted with keys
     - num_of_child increment
   ========================================================= */
BOOLEAN test_add_child16_insert_begin()
{
    TEST_START("add_child16: direct insert at beginning");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "4-pre: alloc node");

    // Keys: 0x30,31,32
    TEST_ASSERT(t_seed_node16_sorted(n, 3, 0x30), "4-pre: seed 3 keys");

    ART_NODE* newCh = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newCh != NULL, "4-pre: new child");

    // Remember old child pointers
    ART_NODE* old0 = n->children[0];
    ART_NODE* old1 = n->children[1];
    ART_NODE* old2 = n->children[2];

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child16(n, &ref, 0x20 /* smaller than all */, newCh);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: insert smaller should succeed");
    TEST_ASSERT(n->base.num_of_child == 4, "4.2: count incremented");

    // Expected order: 0x20,30,31,32
    TEST_ASSERT(n->keys[0] == 0x20 &&
        n->keys[1] == 0x30 &&
        n->keys[2] == 0x31 &&
        n->keys[3] == 0x32, "4.3: keys sorted with new at front");

    TEST_ASSERT(n->children[0] == newCh &&
        n->children[1] == old0 &&
        n->children[2] == old1 &&
        n->children[3] == old2, "4.4: children shifted with keys");

    TEST_ASSERT(ref == (ART_NODE*)n, "4.5: ref unchanged in direct path");

    // cleanup
    n->children[0] = NULL;  // newCh was inserted at index 0 in this test
    t_free(newCh);
    n->children[1] = NULL;
    n->children[2] = NULL;
    n->children[3] = NULL;
    t_free(old0); 
    t_free(old1); 
    t_free(old2);
    t_free(n);

    TEST_END("add_child16: direct insert at beginning");
    return TRUE;
}

/* =========================================================
   Test 5: Direct insert — insertion in the middle (shift tail)
   ========================================================= */
BOOLEAN test_add_child16_insert_middle()
{
    TEST_START("add_child16: direct insert in middle");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "5-pre: alloc node");

    // Keys: 0x10, 0x20, 0x40
    TEST_ASSERT(t_seed_node16_sorted(n, 3, 0x10), "5-pre: seed 3 keys"); // 0x10,11,12 (we want 0x10,0x20,0x40)
    // Fix to exact desired values:
    n->keys[0] = 0x10; // keep child
    n->keys[1] = 0x20;
    n->keys[2] = 0x40;

    ART_NODE* newCh = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(newCh != NULL, "5-pre: new child");

    ART_NODE* c0 = n->children[0];
    ART_NODE* c1 = n->children[1];
    ART_NODE* c2 = n->children[2];

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child16(n, &ref, 0x30 /* between 0x20 and 0x40 */, newCh);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: insert middle should succeed");
    TEST_ASSERT(n->base.num_of_child == 4, "5.2: count=4");

    // Expected keys: 0x10, 0x20, 0x30, 0x40
    TEST_ASSERT(n->keys[0] == 0x10 && n->keys[1] == 0x20 &&
        n->keys[2] == 0x30 && n->keys[3] == 0x40, "5.3: sorted keys");

    // Children mapping after insert at idx=2
    TEST_ASSERT(n->children[0] == c0 &&
        n->children[1] == c1 &&
        n->children[2] == newCh &&
        n->children[3] == c2, "5.4: children shifted correctly");

    TEST_ASSERT(ref == (ART_NODE*)n, "5.5: ref unchanged");

    // cleanup
    n->children[2] = NULL;
    t_free(newCh);
    n->children[0] = n->children[1] = n->children[3] = NULL;
    t_free(c0); t_free(c1); t_free(c2);
    t_free(n);

    TEST_END("add_child16: direct insert in middle");
    return TRUE;
}

/* =========================================================
   Test 6: Direct insert — insertion at the end (no shift)
   ========================================================= */
BOOLEAN test_add_child16_insert_end()
{
    TEST_START("add_child16: direct insert at end");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "6-pre: alloc node");

    // Keys: 0x10, 0x20, 0x30
    TEST_ASSERT(t_seed_node16_sorted(n, 3, 0x10), "6-pre: seed 3 keys"); // becomes 0x10,11,12 by helper
    n->keys[0] = 0x10; n->keys[1] = 0x20; n->keys[2] = 0x30;

    ART_NODE* newCh = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newCh != NULL, "6-pre: new child");

    ART_NODE* c0 = n->children[0], * c1 = n->children[1], * c2 = n->children[2];

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child16(n, &ref, 0x40 /* bigger than all */, newCh);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: insert end should succeed");
    TEST_ASSERT(n->base.num_of_child == 4, "6.2: count=4");

    TEST_ASSERT(n->keys[0] == 0x10 && n->keys[1] == 0x20 &&
        n->keys[2] == 0x30 && n->keys[3] == 0x40, "6.3: sorted keys end");

    TEST_ASSERT(n->children[0] == c0 && n->children[1] == c1 &&
        n->children[2] == c2 && n->children[3] == newCh, "6.4: children positions correct");

    TEST_ASSERT(ref == (ART_NODE*)n, "6.5: ref unchanged");

    // cleanup
    n->children[3] = NULL; 
    t_free(newCh);
    n->children[0] = n->children[1] = n->children[2] = NULL;
    t_free(c0); t_free(c1); t_free(c2);
    t_free(n);

    TEST_END("add_child16: direct insert at end");
    return TRUE;
}

/* =========================================================
   Test 7: Multiple inserts keep the array sorted
   ========================================================= */
BOOLEAN test_add_child16_multiple_inserts_sorted()
{
    TEST_START("add_child16: multiple inserts sorted");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "7-pre: alloc node");

    // Start with: 0x20, 0x40, 0x80
    TEST_ASSERT(t_seed_node16_sorted(n, 3, 0x20), "7-pre: seed 3"); // 0x20,21,22 fix to discrete:
    n->keys[0] = 0x20; n->keys[1] = 0x40; n->keys[2] = 0x80;

    // Save original children
    ART_NODE* c0 = n->children[0], * c1 = n->children[1], * c2 = n->children[2];

    // Insert 0x10, 0x30, 0x90, 0x50 (in varying order)
    UCHAR to_add[] = { 0x50, 0x10, 0x90, 0x30 };
    ART_NODE* newCh[RTL_NUMBER_OF(to_add)] = { 0 };

    ART_NODE* ref = (ART_NODE*)n;

    for (ULONG i = 0; i < RTL_NUMBER_OF(to_add); ++i) {
        newCh[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(newCh[i] != NULL, "7-pre: child alloc");

        NTSTATUS st = add_child16(n, &ref, to_add[i], newCh[i]);
        TEST_ASSERT(NT_SUCCESS(st), "7.x: each insert succeeds");
        TEST_ASSERT(ref == (ART_NODE*)n, "7.x: direct path keeps ref unchanged");
    }

    // Verify sorted keys: {0x10, 0x20, 0x30, 0x40, 0x50, 0x80, 0x90}
    UCHAR expect[] = { 0x10,0x20,0x30,0x40,0x50,0x80,0x90 };
    USHORT expect_count = (USHORT)RTL_NUMBER_OF(expect);

    TEST_ASSERT(n->base.num_of_child == expect_count, "7.1: count matches expected");

    for (USHORT i = 0; i < expect_count; i++) {
        TEST_ASSERT(n->keys[i] == expect[i], "7.2: keys remain sorted");
    }

    // cleanup (detach before frees)
    for (USHORT i = 0; i < expect_count; i++) { n->children[i] = NULL; }
    t_free(c0); t_free(c1); t_free(c2);
    for (ULONG i = 0; i < RTL_NUMBER_OF(to_add); ++i) t_free(newCh[i]);
    t_free(n);

    TEST_END("add_child16: multiple inserts sorted");
    return TRUE;
}

/* =========================================================
   Test 8: No internal alloc/free on direct insert path
   ========================================================= */
BOOLEAN test_add_child16_no_allocfree_direct()
{
    TEST_START("add_child16: no alloc/free on direct path");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "8-pre: alloc node");
    TEST_ASSERT(t_seed_node16_sorted(n, 2, 0x10), "8-pre: seed 2");

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "8-pre: new child");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child16(n, &ref, 0x30, ch);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: insert succeed");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.2: direct path should not allocate/free internally");

    // cleanup
    // child likely at end; detach all known slots
    t_free_children16(n);
    t_free(n);

    TEST_END("add_child16: no alloc/free on direct path");
    return TRUE;
}

/* =========================================================
   Test 9: Full node , expand to NODE48 (happy path)
   Verifies:
     - *ref updated to new NODE48
     - existing (16) children copied to new_node->children[0..15]
     - child_index built (key -> slot+1)
     - new child inserted via add_child48
     - old node freed (free counter increases)
   ========================================================= */
BOOLEAN test_add_child16_expand_to_48_success()
{
    TEST_START("add_child16: expand to NODE48 (success)");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "9-pre: alloc node");

    // Fill 16 entries with sorted keys: 0x10..0x1F (16 items)
    for (USHORT i = 0; i < 16; i++) {
        n->keys[i] = (UCHAR)(0x10 + i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(n->children[i] != NULL, "9-pre: child alloc");
    }
    n->base.num_of_child = 16;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "9-pre: new child");

    ULONG free_before = g_free_call_count;

    // Insert a key not present, e.g., 0x05 (smaller than all)
    NTSTATUS st = add_child16(n, &ref, 0x05, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: expansion must succeed");
    TEST_ASSERT(ref != (ART_NODE*)n, "9.2: ref updated to new NODE48");

    ART_NODE48* n48 = (ART_NODE48*)ref;
    TEST_ASSERT(n48->base.type == NODE48, "9.3: new node type is NODE48");

    // old node freed
    TEST_ASSERT(g_free_call_count >= free_before + 1, "9.4: old NODE16 freed");

    // Existing 16 children copied to new_node (indices 0..15) and child_index set
    for (USHORT i = 0; i < 16; i++) {
        UCHAR key = (UCHAR)(0x10 + i);
        UCHAR idx1b = n48->child_index[key];
        TEST_ASSERT(idx1b != 0, "9.5: child_index set for existing key");
        UCHAR slot = (UCHAR)(idx1b - 1);
        TEST_ASSERT(slot < 48, "9.6: slot in range");
        TEST_ASSERT(n48->children[slot] != NULL, "9.7: child carried over");
    }

    // New child inserted at key 0x05
    TEST_ASSERT(n48->child_index[0x05] != 0, "9.8: new key mapped");
    {
        UCHAR slot1b = n48->child_index[0x05];
        UCHAR slot = (UCHAR)(slot1b - 1);
        TEST_ASSERT(n48->children[slot] == newChild, "9.9: new child stored");
    }

    // Cleanup: detach to avoid double free (we free manually)
    for (int i = 0; i < 48; i++) {
        if (n48->children[i]) { n48->children[i] = NULL; }
    }
    // free copied 16 children + newChild
    for (USHORT i = 0; i < 16; i++) {
        // Recreate pointers to free: they were moved into n48->children[*], but we detached.
        // We kept no direct list; safe approach: free newChild explicitly; old 16 children must still be freed manually.
        // In a real harness you might track them. Here, re-allocate tracking isn't available,
        // so we skip freeing the old 16 to avoid double frees if already freed elsewhere.
        // If you track allocations externally, free them here.
    }
    // Cleanup: free all children mapped in NODE48, including the new child
    for (USHORT i = 0; i < 256; i++) {
        UCHAR idx1b = n48->child_index[i];
        if (idx1b) {
            UCHAR slot = (UCHAR)(idx1b - 1);
            if (slot < 48 && n48->children[slot]) {
                t_free(n48->children[slot]);  // frees both old and new children
                n48->children[slot] = NULL;
            }
            n48->child_index[i] = 0;
        }
    }
    t_free(n48);

    TEST_END("add_child16: expand to NODE48 (success)");
    return TRUE;
}

/* =========================================================
   Test 9b: Expand success — verify new_node->base.num_of_child = 17
   (old 16 + the new inserted child)
   ========================================================= */
BOOLEAN test_add_child16_expand_to_48_count_check()
{
    TEST_START("add_child16: expand to NODE48 (count check)");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "9b-pre: alloc node");

    // Fill 16 sorted keys 0x10..0x1F
    for (USHORT i = 0; i < 16; i++) {
        n->keys[i] = (UCHAR)(0x10 + i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(n->children[i] != NULL, "9b-pre: child alloc");
    }
    n->base.num_of_child = 16;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "9b-pre: new child");

    NTSTATUS st = add_child16(n, &ref, 0x05, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "9b.1: expansion must succeed");
    TEST_ASSERT(ref && ((ART_NODE*)ref)->type == NODE48, "9b.2: ref points to NODE48");

    ART_NODE48* n48 = (ART_NODE48*)ref;

    // Expect header count to be old 16 + 1 (insert)
    TEST_ASSERT(n48->base.num_of_child == 17, "9b.3: new_node->num_of_child must be 17");

    // cleanup: free all mapped children (including newChild)
    for (USHORT i = 0; i < 256; i++) {
        UCHAR idx1b = n48->child_index[i];
        if (idx1b) {
            UCHAR slot = (UCHAR)(idx1b - 1);
            if (slot < 48 && n48->children[slot]) {
                t_free(n48->children[slot]);
                n48->children[slot] = NULL;
            }
            n48->child_index[i] = 0;
        }
    }
    t_free(n48);

    TEST_END("add_child16: expand to NODE48 (count check)");
    return TRUE;
}

/* =========================================================
   Test 10: Full node , expand to NODE48 but art_create_node fails
   Expect:
     - STATUS_INSUFFICIENT_RESOURCES
     - *ref remains old node
     - no frees performed by add_child16
   ========================================================= */
BOOLEAN test_add_child16_expand_alloc_failure()
{
    TEST_START("add_child16: expand , art_create_node alloc failure");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "10-pre: alloc node");

    // Fill 16 entries to force expansion
    for (USHORT i = 0; i < 16; i++) {
        n->keys[i] = (UCHAR)(0x40 + i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(n->children[i] != NULL, "10-pre: child alloc");
    }
    n->base.num_of_child = 16;

    ART_NODE* ref = (ART_NODE*)n;

    // New child is allocated BEFORE we trigger alloc-fail,
    // so the next allocation (NODE48 creation) fails.
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "10-pre: new child alloc");

    // Fail the very next ExAllocatePool2 call
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, g_alloc_call_count);

    ULONG frees_before = g_free_call_count;
    NTSTATUS st = add_child16(n, &ref, 0x10 /* key not present */, newChild);

    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "10.1: must return INSUFFICIENT_RESOURCES");
    TEST_ASSERT(ref == (ART_NODE*)n, "10.2: ref must remain the old NODE16");
    TEST_ASSERT(g_free_call_count == frees_before, "10.3: no frees performed on early alloc failure");

    // restore allocator
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0);

    // cleanup: detach and free all 16 old children + newChild
    for (USHORT i = 0; i < 16; i++) { t_free(n->children[i]); n->children[i] = NULL; }
    t_free(newChild);
    t_free(n);

    TEST_END("add_child16: expand , art_create_node alloc failure");
    return TRUE;
}


/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_add_child16_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting add_child16() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_add_child16_guards())                      all_passed = FALSE; // 1
    if (!test_add_child16_wrong_type())                  all_passed = FALSE; // 2
    if (!test_add_child16_duplicate_key())               all_passed = FALSE; // 3
    if (!test_add_child16_insert_begin())                all_passed = FALSE; // 4
    if (!test_add_child16_insert_middle())               all_passed = FALSE; // 5
    if (!test_add_child16_insert_end())                  all_passed = FALSE; // 6
    if (!test_add_child16_multiple_inserts_sorted())     all_passed = FALSE; // 7
    if (!test_add_child16_no_allocfree_direct())         all_passed = FALSE; // 8
    if (!test_add_child16_expand_to_48_success())        all_passed = FALSE; // 9
    if (!test_add_child16_expand_to_48_count_check())    all_passed = FALSE; // 9b
    if (!test_add_child16_expand_alloc_failure())        all_passed = FALSE; // 10


    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL add_child16() TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME add_child16() TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
