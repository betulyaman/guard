// ========================= test_add_child.c =========================
#include "test_art.h"

// Function under test
STATIC NTSTATUS add_child(_Inout_ ART_NODE* node,
    _Inout_ ART_NODE** ref,
    _In_ UCHAR c,
    _In_ PVOID child);

/*
   Test 1: Guard checks
   */
BOOLEAN test_add_child_guards()
{
    TEST_START("add_child: guards");

    reset_mock_state();

    ART_NODE* hdr = t_alloc_header_only(NODE4);
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(hdr && ch, "1-pre: allocations");

#pragma warning(push)
#pragma warning(disable: 4566 6387)
    NTSTATUS st;
    st = add_child(NULL, NULL, 0, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node rejected");

    st = add_child(hdr, NULL, 1, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref rejected");

    st = add_child(hdr, &hdr, 2, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: NULL child rejected");
#pragma warning(pop)

    t_free(ch);
    t_free(hdr);

    TEST_END("add_child: guards");
    return TRUE;
}

/*
   Test 2: Invalid node type dispatch
   */
BOOLEAN test_add_child_invalid_type()
{
    TEST_START("add_child: invalid node type");

    reset_mock_state();

    ART_NODE* hdr = t_alloc_header_only((NODE_TYPE)0x77); // invalid
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(hdr && ch, "2-pre: allocations");

    ART_NODE* ref = hdr;
    NTSTATUS st = add_child(hdr, &ref, 0x11, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: invalid type rejected");
    TEST_ASSERT(ref == hdr, "2.2: ref unchanged on reject");

    t_free(ch);
    t_free(hdr);

    TEST_END("add_child: invalid node type");
    return TRUE;
}

/*
   Test 3: Dispatch to NODE4 (direct insert success)
   */
BOOLEAN test_add_child_dispatch_node4_success()
{
    TEST_START("add_child: dispatch , NODE4 success");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "3-pre: node4 alloc");
    TEST_ASSERT(t_seed_node4_sorted(n, 2, 0x20), "3-pre: seed 0x20,0x21");

    ART_NODE* child = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(child != NULL, "3-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x30, child);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: add succeeds");
    TEST_ASSERT(ref == (ART_NODE*)n, "3.2: ref unchanged in direct path");
    TEST_ASSERT(n->base.num_of_child == 3, "3.3: count incremented");
    TEST_ASSERT(n->keys[2] == 0x30 && n->children[2] == child, "3.4: inserted at end");

    // cleanup
    t_free_children4(n);
    t_free(n);

    TEST_END("add_child: dispatch , NODE4 success");
    return TRUE;
}

/*
   Test 4: Dispatch to NODE4 (duplicate bubbles collision)
   */
BOOLEAN test_add_child_dispatch_node4_duplicate()
{
    TEST_START("add_child: dispatch , NODE4 duplicate");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "4-pre: node4 alloc");
    TEST_ASSERT(t_seed_node4_sorted(n, 2, 0x40), "4-pre: seed 0x40,0x41");

    ART_NODE* child = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(child != NULL, "4-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x40, child);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "4.1: duplicate bubbled from add_child4");
    TEST_ASSERT(ref == (ART_NODE*)n, "4.2: ref unchanged on error");

    t_free_children4(n);
    t_free(child);
    t_free(n);

    TEST_END("add_child: dispatch , NODE4 duplicate");
    return TRUE;
}

/*
   Test 5: Dispatch to NODE16 (direct insert success)
   */
BOOLEAN test_add_child_dispatch_node16_success()
{
    TEST_START("add_child: dispatch , NODE16 success");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "5-pre: node16 alloc");
    TEST_ASSERT(t_seed_node16_sorted(n, 2, 0x10), "5-pre: seed 0x10,0x11");

    ART_NODE* child = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(child != NULL, "5-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x20, child);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: add succeeds");
    TEST_ASSERT(ref == (ART_NODE*)n, "5.2: ref unchanged");
    TEST_ASSERT(n->base.num_of_child == 3, "5.3: count incremented");

    // cleanup
    t_free(child);
    t_free_children16(n);
    t_free(n);

    TEST_END("add_child: dispatch , NODE16 success");
    return TRUE;
}

/*
   Test 6: Dispatch to NODE48 (direct insert success)
   */
BOOLEAN test_add_child_dispatch_node48_success()
{
    TEST_START("add_child: dispatch , NODE48 success");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    TEST_ASSERT(n != NULL, "6-pre: node48 alloc");
    // empty map/children; add one
    ART_NODE* child = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(child != NULL, "6-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x55, child);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: add succeeds");
    TEST_ASSERT(ref == (ART_NODE*)n, "6.2: ref unchanged");
    TEST_ASSERT(n->base.num_of_child == 1, "6.3: count=1");
    TEST_ASSERT(n->child_index[0x55] != 0, "6.4: index set");
    {
        UCHAR slot = (UCHAR)(n->child_index[0x55] - 1);
        TEST_ASSERT(slot < 48 && n->children[slot] == child, "6.5: child stored");
    }

    // cleanup
    if (n->child_index[0x55]) {
        UCHAR slot = (UCHAR)(n->child_index[0x55] - 1);
        n->children[slot] = NULL;
    }
    t_free(child);
    t_free_children48(n);
    t_free(n);

    TEST_END("add_child: dispatch , NODE48 success");
    return TRUE;
}

/*
   Test 7: Dispatch to NODE256 (direct insert success)
   */
BOOLEAN test_add_child_dispatch_node256_success()
{
    TEST_START("add_child: dispatch , NODE256 success");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    TEST_ASSERT(n != NULL, "7-pre: node256 alloc");

    ART_NODE* child = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(child != NULL, "7-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0xA1, child);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: add succeeds");
    TEST_ASSERT(ref == (ART_NODE*)n, "7.2: ref unchanged");
    TEST_ASSERT(n->base.num_of_child == 1, "7.3: count=1");
    TEST_ASSERT(n->children[0xA1] == child, "7.4: child set at index");

    // cleanup
    n->children[0xA1] = NULL;
    t_free(child);
    t_free_children256(n);
    t_free(n);

    TEST_END("add_child: dispatch , NODE256 success");
    return TRUE;
}

/*
   Test 8: Dispatch to NODE256 collision bubbles up
   */
BOOLEAN test_add_child_dispatch_node256_collision()
{
    TEST_START("add_child: dispatch , NODE256 collision");

    reset_mock_state();

    ART_NODE256* n = t_alloc_node256();
    TEST_ASSERT(n != NULL, "8-pre: node256 alloc");

    ART_NODE* childA = t_alloc_dummy_child(NODE4);
    ART_NODE* childB = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(childA && childB, "8-pre: children alloc");

    ART_NODE* ref = (ART_NODE*)n;

    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x7F, childA);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: first add ok");
    TEST_ASSERT(n->children[0x7F] == childA, "8.1: set");

    st = add_child((ART_NODE*)n, &ref, 0x7F, childB);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "8.2: collision bubbled from add_child256");
    TEST_ASSERT(n->children[0x7F] == childA, "8.3: original child intact");

    n->children[0x7F] = NULL;
    t_free(childA); t_free(childB);
    t_free_children256(n);
    t_free(n);

    TEST_END("add_child: dispatch , NODE256 collision");
    return TRUE;
}

/*
   Test 9: Dispatch covers NODE4 expansion path (ref updated)
   (Fill NODE4 with 4 items, add one more , expands to NODE16 via add_child4)
   */
BOOLEAN test_add_child_dispatch_node4_expand_updates_ref()
{
    TEST_START("add_child: NODE4 expansion updates ref");

    reset_mock_state();

    ART_NODE4* n = t_alloc_node4();
    TEST_ASSERT(n != NULL, "9-pre: node4 alloc");

    // Fill 4 slots: 0x10,0x20,0x30,0x40
    TEST_ASSERT(t_seed_node4_sorted(n, 4, 0x10), "9-pre: seed 4");
    n->keys[0] = 0x10; n->keys[1] = 0x20; n->keys[2] = 0x30; n->keys[3] = 0x40;

    ART_NODE* newChild = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(newChild != NULL, "9-pre: new child");

    ART_NODE* ref = (ART_NODE*)n;
    ULONG frees_before = g_free_call_count;

    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x05, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: expansion succeeds");
    TEST_ASSERT(ref != (ART_NODE*)n, "9.2: ref updated by underlying add_child4");

    // New ref must be NODE16 (per add_child4’s expansion logic)
    ART_NODE16* n16 = (ART_NODE16*)ref;
    TEST_ASSERT(n16->base.type == NODE16, "9.3: new type is NODE16");

    TEST_ASSERT(g_free_call_count >= frees_before + 1, "9.x: old NODE4 freed (>= +1)");

    // New key must exist somewhere in n16
    BOOLEAN found = FALSE;
    for (USHORT i = 0; i < n16->base.num_of_child; i++) {
        if (n16->keys[i] == 0x05) {
            TEST_ASSERT(n16->children[i] == newChild, "9.4: new child stored at new ref");
            found = TRUE;
            break;
        }
    }
    TEST_ASSERT(found, "9.5: new key present in expanded node");

    // cleanup
    t_free_children16(n16);  // frees *all* children at the new node
    t_free(n16);

    TEST_END("add_child: NODE4 expansion updates ref");
    return TRUE;
}

/*
   NEW 10: Dispatch covers NODE16 expansion path (ref updated to NODE48)
*/
BOOLEAN test_add_child_dispatch_node16_expand_updates_ref()
{
    TEST_START("add_child: NODE16 expansion updates ref");

    reset_mock_state();

    ART_NODE16* n = t_alloc_node16();
    TEST_ASSERT(n != NULL, "10-pre: node16 alloc");

    // Fill 16 sorted keys: 0x10..0x1F
    for (USHORT i = 0; i < 16; i++) {
        n->keys[i] = (UCHAR)(0x10 + i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(n->children[i] != NULL, "10-pre: child alloc");
    }
    n->base.num_of_child = 16;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "10-pre: new child");

    NTSTATUS st = add_child((ART_NODE*)n, &ref, 0x05 /* new minimum */, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "10.1: expansion must succeed");
    TEST_ASSERT(ref != (ART_NODE*)n, "10.2: ref updated");

    ART_NODE48* n48 = (ART_NODE48*)ref;
    TEST_ASSERT(n48->base.type == NODE48, "10.3: new node is NODE48");

    // New key present
    TEST_ASSERT(n48->child_index[0x05] != 0, "10.4: new key mapped");
    {
        UCHAR slot = (UCHAR)(n48->child_index[0x05] - 1);
        TEST_ASSERT(slot < 48 && n48->children[slot] == newChild, "10.5: new child stored");
    }

    // cleanup: free all mapped children in NODE48
    for (USHORT i = 0; i < 256; i++) {
        UCHAR m = n48->child_index[i];
        if (m) {
            UCHAR slot = (UCHAR)(m - 1);
            if (slot < 48 && n48->children[slot]) {
                t_free(n48->children[slot]);
                n48->children[slot] = NULL;
            }
            n48->child_index[i] = 0;
        }
    }
    t_free(n48);

    TEST_END("add_child: NODE16 expansion updates ref");
    return TRUE;
}

/*
   NEW 11: Dispatch covers NODE48 expansion path (ref updated to NODE256)
*/
BOOLEAN test_add_child_dispatch_node48_expand_updates_ref()
{
    TEST_START("add_child: NODE48 expansion updates ref");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    TEST_ASSERT(n != NULL, "11-pre: node48 alloc");

    // Seed a couple of valid mappings; mark node full to force expansion
    ART_NODE* a = t_alloc_dummy_child(NODE4);
    ART_NODE* b = t_alloc_dummy_child(NODE4);
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(a && b && newChild, "11-pre: child allocs");

    n->children[0] = a; n->child_index[1] = 1; // key=1   -> slot0
    n->children[1] = b; n->child_index[200] = 2; // key=200 -> slot1
    n->base.num_of_child = 48; // triggers expand branch

    ART_NODE* ref = (ART_NODE*)n;

    NTSTATUS st = add_child((ART_NODE*)n, &ref, 7 /* new key */, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "11.1: expansion must succeed");
    TEST_ASSERT(ref != (ART_NODE*)n, "11.2: ref updated");
    ART_NODE256* n256 = (ART_NODE256*)ref;
    TEST_ASSERT(n256->base.type == NODE256, "11.3: new node is NODE256");

    // Existing carried and new inserted
    TEST_ASSERT(n256->children[1] == a, "11.4: key=1 carried over");
    TEST_ASSERT(n256->children[200] == b, "11.5: key=200 carried over");
    TEST_ASSERT(n256->children[7] == newChild, "11.6: new child inserted");

    // cleanup
    n256->children[1] = NULL;
    n256->children[200] = NULL;
    n256->children[7] = NULL;
    t_free(a); t_free(b); t_free(newChild);
    t_free(n256);

    TEST_END("add_child: NODE48 expansion updates ref");
    return TRUE;
}

/*
   Suite Runner
   */
NTSTATUS run_all_add_child_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting add_child() Dispatcher Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_add_child_guards())                          all_passed = FALSE; // 1
    if (!test_add_child_invalid_type())                    all_passed = FALSE; // 2
    if (!test_add_child_dispatch_node4_success())          all_passed = FALSE; // 3
    if (!test_add_child_dispatch_node4_duplicate())        all_passed = FALSE; // 4
    if (!test_add_child_dispatch_node16_success())         all_passed = FALSE; // 5
    if (!test_add_child_dispatch_node48_success())         all_passed = FALSE; // 6
    if (!test_add_child_dispatch_node256_success())        all_passed = FALSE; // 7
    if (!test_add_child_dispatch_node256_collision())      all_passed = FALSE; // 8
    if (!test_add_child_dispatch_node4_expand_updates_ref()) all_passed = FALSE; // 9
    if (!test_add_child_dispatch_node16_expand_updates_ref()) all_passed = FALSE; // 10
    if (!test_add_child_dispatch_node48_expand_updates_ref()) all_passed = FALSE; // 11

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL add_child() DISPATCH TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME add_child() DISPATCH TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
