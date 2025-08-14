#if UNIT_TEST
#include "test_art.h"

// Function under test
STATIC NTSTATUS add_child48(_Inout_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);

//=========================================================
// Test 1: Guard checks (NULL node/ref/child)
//=========================================================
BOOLEAN test_add_child48_guards()
{
    TEST_START("add_child48: guards");

    reset_mock_state();

    ART_NODE48* n48 = t_alloc_node48();          // optional for non-NULL node
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "1-pre: child alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    NTSTATUS st;


#pragma warning(push)
#pragma warning(disable: 6387)
    st = add_child48(NULL, NULL, 0, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node rejected");

    st = add_child48(n48, NULL, 1, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref rejected");

    st = add_child48(n48, (ART_NODE**)&n48, 2, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: NULL child rejected");
#pragma warning(pop)

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no internal alloc/free on guards");

    t_free(ch);
    t_free(n48);

    TEST_END("add_child48: guards");
    return TRUE;
}

//=========================================================
// Test 2: Wrong node type
//=========================================================
BOOLEAN test_add_child48_wrong_type()
{
    TEST_START("add_child48: wrong type");

    reset_mock_state();

    ART_NODE48* n48_like = (ART_NODE48*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE48), ART_TAG);
    TEST_ASSERT(n48_like != NULL, "2-pre: alloc fake node48");
    RtlZeroMemory(n48_like, sizeof(*n48_like));
    n48_like->base.type = NODE16; // wrong type

    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(ch != NULL, "2-pre: child alloc");

    ART_NODE* ref = (ART_NODE*)n48_like;
    NTSTATUS st = add_child48(n48_like, &ref, 10, ch);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: non-NODE48 must be rejected");
    TEST_ASSERT(ref == (ART_NODE*)n48_like, "2.2: ref must stay unchanged on reject");
    TEST_ASSERT(n48_like->base.num_of_child == 0, "2.3: count unchanged");

    t_free(ch);
    t_free(n48_like);

    TEST_END("add_child48: wrong type");
    return TRUE;
}

//=========================================================
// Test 3: Collision in index map (child_index[c] != 0)
//=========================================================
BOOLEAN test_add_child48_collision()
{
    TEST_START("add_child48: collision");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    ART_NODE* chA = t_alloc_dummy_child(NODE4);
    ART_NODE* chB = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(n && chA && chB, "3-pre: allocations ok");

    // Pre-occupy key 'c' at slot 0
    UCHAR c = 123;
    n->children[0] = chA;
    n->child_index[c] = 0 + 1; // 1
    n->base.num_of_child = 1;

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child48(n, &ref, c, chB);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "3.1: existing key , collision");
    TEST_ASSERT(n->base.num_of_child == 1, "3.2: count must not increment");
    TEST_ASSERT(n->child_index[c] == 1 && n->children[0] == chA, "3.3: mapping unchanged");
    TEST_ASSERT(ref == (ART_NODE*)n, "3.4: ref unchanged on collision");

    t_free(chB);
    // free node + pre-existing child
    n->children[0] = NULL;
    t_free(chA);
    t_free(n);

    TEST_END("add_child48: collision");
    return TRUE;
}

//=========================================================
// Test 4: Direct insert (capacity available) — success
// 4.1 first free slot is 0
// 4.2 first free slot is not 0
//=========================================================
BOOLEAN test_add_child48_direct_insert_success()
{
    TEST_START("add_child48: direct insert success");

    // (4.1) empty node: pos=0
    reset_mock_state();
    {
        ART_NODE48* n = t_alloc_node48();
        ART_NODE* ch = t_alloc_dummy_child(NODE16);
        TEST_ASSERT(n && ch, "4.1-pre: alloc");

        ART_NODE* ref = (ART_NODE*)n; // should remain unchanged in this branch
        NTSTATUS st = add_child48(n, &ref, 7, ch);
        TEST_ASSERT(NT_SUCCESS(st), "4.1: should succeed");
        TEST_ASSERT(n->base.num_of_child == 1, "4.1: count=1");
        TEST_ASSERT(n->child_index[7] == 1, "4.1: index maps to slot 0 (1-based)");
        TEST_ASSERT(n->children[0] == ch, "4.1: child placed at slot 0");
        TEST_ASSERT(ref == (ART_NODE*)n, "4.1: ref unchanged");

        // cleanup
        n->children[0] = NULL;
        t_free(ch);
        t_free(n);
    }

    // (4.2) slot 0 used, should pick next free slot
    reset_mock_state();
    {
        ART_NODE48* n = t_alloc_node48();
        ART_NODE* ch0 = t_alloc_dummy_child(NODE4);
        ART_NODE* ch1 = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(n && ch0 && ch1, "4.2-pre: alloc");

        n->children[0] = ch0;
        n->base.num_of_child = 1;

        ART_NODE* ref = (ART_NODE*)n;
        NTSTATUS st = add_child48(n, &ref, 200, ch1);
        TEST_ASSERT(NT_SUCCESS(st), "4.2: should succeed");
        TEST_ASSERT(n->base.num_of_child == 2, "4.2: count=2");
        TEST_ASSERT(n->child_index[200] == 2, "4.2: index maps to slot 1 (2)");
        TEST_ASSERT(n->children[1] == ch1, "4.2: child placed at slot 1");
        TEST_ASSERT(ref == (ART_NODE*)n, "4.2: ref unchanged");

        // cleanup
        n->children[0] = NULL;
        n->children[1] = NULL;
        t_free(ch1);
        t_free(ch0);
        t_free(n);
    }

    TEST_END("add_child48: direct insert success");
    return TRUE;
}

//=========================================================
// Test 5: Inconsistent state (count<48 but no free slot) , INTERNAL_ERROR
//=========================================================
BOOLEAN test_add_child48_inconsistent_state()
{
    TEST_START("add_child48: inconsistent state");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    ART_NODE* kids[48];
    TEST_ASSERT(n, "5-pre: node alloc");

    // Fill all 48 slots non-NULL
    for (int i = 0; i < 48; i++) {
        kids[i] = t_alloc_dummy_child(NODE4);
        TEST_ASSERT(kids[i] != NULL, "5-pre: child alloc");
        n->children[i] = kids[i];
    }
    n->base.num_of_child = 47; // <48 but loop will see no free slot , inconsistent

    ART_NODE* chX = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(chX != NULL, "5-pre: extra child");

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child48(n, &ref, 5, chX);
    TEST_ASSERT(st == STATUS_INTERNAL_ERROR, "5.1: must return INTERNAL_ERROR when no free slot but count<48");
    TEST_ASSERT(ref == (ART_NODE*)n, "5.2: ref unchanged");

    // cleanup
    for (int i = 0; i < 48; i++) { t_free(kids[i]); n->children[i] = NULL; }
    t_free(chX);
    t_free(n);

    TEST_END("add_child48: inconsistent state");
    return TRUE;
}

//=========================================================
// Test 6: Full node , expand to NODE256 (happy path)
//  - copy existing children to new 256-node
//  - copy_header called (header copied)
//  - add new child via add_child256
//  - *ref updated; old node freed
//=========================================================
BOOLEAN test_add_child48_expand_success()
{
    TEST_START("add_child48: expand to NODE256 (success)");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    TEST_ASSERT(n != NULL, "6-pre: node48 alloc");

    // Fill some children and child_index mapping
    // Use two fixed keys, e.g., 1 -> slot0, 250 -> slot1
    ART_NODE* a = t_alloc_dummy_child(NODE4);
    ART_NODE* b = t_alloc_dummy_child(NODE4);
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(a && b && newChild, "6-pre: child allocs");

    n->children[0] = a; n->child_index[1] = 1; // key=1, slot0
    n->children[1] = b; n->child_index[250] = 2; // key=250, slot1
    n->base.num_of_child = 48;  // mark as full to trigger expansion

    ART_NODE* ref = (ART_NODE*)n; // will be updated to new NODE256

    ULONG free_before = g_free_call_count;
    NTSTATUS st = add_child48(n, &ref, 7 /*new key*/, newChild);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: expansion must succeed");
    TEST_ASSERT(ref != (ART_NODE*)n, "6.2: ref must point to new NODE256");
    TEST_ASSERT(ref && ((ART_NODE256*)ref)->base.type == NODE256, "6.3: new node is NODE256");

    // Old node should be freed by free_node()
    TEST_ASSERT(g_free_call_count >= free_before + 1, "6.4: old node freed");

    // Verify copied children and placed new child
    ART_NODE256* n256 = (ART_NODE256*)ref;
    TEST_ASSERT(n256->children[1] == a, "6.5: existing child key=1 copied");
    TEST_ASSERT(n256->children[250] == b, "6.6: existing child key=250 copied");
    TEST_ASSERT(n256->children[7] == newChild, "6.7: new child inserted at key=7");

    // Clean up: detach to avoid double free (we free them manually)
    n256->children[1] = NULL;
    n256->children[250] = NULL;
    n256->children[7] = NULL;

    t_free(a);
    t_free(b);
    t_free(newChild);
    t_free(n256); // ref

    TEST_END("add_child48: expand to NODE256 (success)");
    return TRUE;
}

//=========================================================
// Test 7: Full node , expand but copy loop finds invalid child index
//         (node->child_index[i] -> pos >= 48) , STATUS_DATA_ERROR
//         new_node must be freed (no leak), *ref must remain old node
//=========================================================
BOOLEAN test_add_child48_expand_copy_data_error()
{
    TEST_START("add_child48: expand , data error in copy loop");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    TEST_ASSERT(n != NULL, "7-pre: node48 alloc");

    // Put an invalid mapping: child_index[x] = 255 (=> pos=254 >= 48)
    n->child_index[42] = 255; // pos = 254 (invalid)
    n->base.num_of_child = 48; // trigger expansion

    ART_NODE* dummyChild = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(dummyChild != NULL, "7-pre: new child alloc");

    ART_NODE* ref = (ART_NODE*)n;
    ULONG free_before = g_free_call_count;

    NTSTATUS st = add_child48(n, &ref, 7, dummyChild);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "7.1: invalid mapping must return DATA_ERROR");
    TEST_ASSERT(ref == (ART_NODE*)n, "7.2: ref must remain old node on failure");

    // A temporary NODE256 was allocated then freed in cleanup
    TEST_ASSERT(g_free_call_count >= free_before + 1, "7.3: temporary NODE256 freed in cleanup");

    // cleanup
    t_free(dummyChild);
    t_free(n);

    TEST_END("add_child48: expand , data error in copy loop");
    return TRUE;
}

//=========================================================
// Test 8: No internal alloc/free on direct insert path
//         (the function should not allocate or free memory
//          when capacity < 48; it only writes pointers)
//=========================================================
BOOLEAN test_add_child48_no_allocfree_on_direct()
{
    TEST_START("add_child48: no alloc/free on direct path");

    reset_mock_state();

    ART_NODE48* n = t_alloc_node48();
    ART_NODE* ch = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(n && ch, "8-pre: alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    ART_NODE* ref = (ART_NODE*)n;
    NTSTATUS st = add_child48(n, &ref, 9, ch);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: should succeed");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "8.2: no internal alloc/free on direct path");

    // cleanup
    n->children[0] = NULL; // slot 0 used
    t_free(ch);
    t_free(n);

    TEST_END("add_child48: no alloc/free on direct path");
    return TRUE;
}

/* =========================================================
   Test 9: Full node , expand but art_create_node fails
            (simulate allocation failure) , STATUS_INSUFFICIENT_RESOURCES
            *ref must remain old node; no children moved; no leaks
   ========================================================= */
BOOLEAN test_add_child48_expand_alloc_failure()
{
    TEST_START("add_child48: expand , art_create_node alloc failure");

    reset_mock_state();

    // Prepare a full NODE48 to trigger expansion
    ART_NODE48* n = t_alloc_node48();
    TEST_ASSERT(n != NULL, "9-pre: node48 alloc");

    // Seed a couple of valid mappings so we'd try to copy them (if alloc worked)
    ART_NODE* a = t_alloc_dummy_child(NODE4);
    ART_NODE* b = t_alloc_dummy_child(NODE4);
    TEST_ASSERT(a && b, "9-pre: child allocs");

    n->children[0] = a; n->child_index[1] = 1; // key=1 -> slot 0
    n->children[1] = b; n->child_index[200] = 2; // key=200 -> slot 1
    n->base.num_of_child = 48;                    // mark as full

    ART_NODE* ref = (ART_NODE*)n;

    // Simulate allocation failure on the very next allocation call.
    // art_create_node(NODE256) should be the first allocation in the branch.
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 0); // fail first alloc

    ULONG free_before = g_free_call_count;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16);
    TEST_ASSERT(newChild != NULL, "9-pre: new child alloc");
    NTSTATUS st = add_child48(n, &ref, 7, newChild);
    t_free(newChild);

    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "9.1: must return INSUFFICIENT_RESOURCES when NODE256 alloc fails");
    TEST_ASSERT(ref == (ART_NODE*)n, "9.2: ref must remain pointing at old NODE48 on failure");
    TEST_ASSERT(g_free_call_count == free_before, "9.3: no frees performed by add_child48 on early alloc failure");

    // cleanup
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0); // restore
    // detach pre-seeded children and free them & node
    n->children[0] = NULL;
    n->children[1] = NULL;
    t_free(a);
    t_free(b);
    t_free(n);

    TEST_END("add_child48: expand , art_create_node alloc failure");
    return TRUE;
}

BOOLEAN test_add_child48_expand_dup_slot_mapping_fails()
{
    TEST_START("add_child48: expand, duplicate slot mapping -> DATA_ERROR");

    reset_mock_state();
    ART_NODE48* n = t_alloc_node48(); TEST_ASSERT(n, "pre");
    ART_NODE* ch0 = t_alloc_dummy_child(NODE4); TEST_ASSERT(ch0, "pre");
    n->children[0] = ch0;
    n->child_index[10] = 1;  // slot 0
    n->child_index[11] = 1;  // aynı slot -> korupsyon
    n->base.num_of_child = 48;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16); TEST_ASSERT(newChild, "pre");

    ULONG free_before = g_free_call_count;
    NTSTATUS st = add_child48(n, &ref, 7, newChild);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "duplicate slot mapping -> DATA_ERROR");
    TEST_ASSERT(ref == (ART_NODE*)n, "ref unchanged on failure");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "temp NODE256 freed");

    // cleanup
    n->children[0] = NULL;
    t_free(newChild); t_free(ch0); t_free(n);
    TEST_END("add_child48: expand, duplicate slot mapping -> DATA_ERROR");
    return TRUE;
}

BOOLEAN test_add_child48_expand_unmapped_child_fails()
{
    TEST_START("add_child48: expand, child present but unmapped -> DATA_ERROR");

    reset_mock_state();
    ART_NODE48* n = t_alloc_node48(); TEST_ASSERT(n, "pre");
    ART_NODE* stray = t_alloc_dummy_child(NODE4); TEST_ASSERT(stray, "pre");
    n->children[5] = stray; // map yok
    n->base.num_of_child = 48;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16); TEST_ASSERT(newChild, "pre");

    NTSTATUS st = add_child48(n, &ref, 7, newChild);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "add_child48: DATA_ERROR");

    // cleanup
    n->children[5] = NULL;
    t_free(newChild); t_free(stray); t_free(n);
    TEST_END("add_child48: expand, child present but unmapped -> DATA_ERROR");
    return TRUE;
}

BOOLEAN test_add_child48_expand_add_child256_collision()
{
    TEST_START("add_child48: expand, add_child256 collision");

    reset_mock_state();
    ART_NODE48* n = t_alloc_node48(); TEST_ASSERT(n, "pre");
    ART_NODE* old = t_alloc_dummy_child(NODE4); TEST_ASSERT(old, "pre");
    n->children[0] = old;
    n->child_index[7] = 1;  // key 7 zaten var
    n->base.num_of_child = 48;

    ART_NODE* ref = (ART_NODE*)n;
    ART_NODE* newChild = t_alloc_dummy_child(NODE16); TEST_ASSERT(newChild, "pre");

    ULONG free_before = g_free_call_count;
    NTSTATUS st = add_child48(n, &ref, 7, newChild);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "collision bubbles up");
    TEST_ASSERT(ref == (ART_NODE*)n, "ref unchanged");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "temp NODE256 freed");

    // cleanup
    n->children[0] = NULL;
    t_free(newChild); t_free(old); t_free(n);
    TEST_END("add_child48: expand, add_child256 collision");
    return TRUE;
}

//=========================================================
// Suite Runner
//=========================================================
NTSTATUS run_all_add_child48_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting add_child48() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_add_child48_guards())                    all_passed = FALSE; // 1
    if (!test_add_child48_wrong_type())                all_passed = FALSE; // 2
    if (!test_add_child48_collision())                 all_passed = FALSE; // 3
    if (!test_add_child48_direct_insert_success())     all_passed = FALSE; // 4
    if (!test_add_child48_inconsistent_state())        all_passed = FALSE; // 5
    if (!test_add_child48_expand_success())            all_passed = FALSE; // 6
    if (!test_add_child48_expand_copy_data_error())    all_passed = FALSE; // 7
    if (!test_add_child48_no_allocfree_on_direct())    all_passed = FALSE; // 8
    if (!test_add_child48_expand_alloc_failure())      all_passed = FALSE; // 9
    if (!test_add_child48_expand_add_child256_collision())  all_passed = FALSE;


    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL add_child48() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME add_child48() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif