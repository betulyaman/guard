#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child256(_In_ ART_NODE256* node,
    _Inout_ ART_NODE** ref,
    _In_ UCHAR c);

// ---- Fault-injection convenience (normalize usage across tests) ----
#ifndef FI_ON_NEXT_ALLOC
#define FI_ON_NEXT_ALLOC() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, g_alloc_call_count)
#endif
#ifndef FI_OFF
#define FI_OFF() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0)
#endif

// ---------- tiny local helpers (no CRT) ----------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE256* t_make_node256_with_children_count(USHORT count, UCHAR start_key,
    ART_NODE** out_ref_saved,
    ART_LEAF** out_leaves, USHORT out_leaves_cap)
{
    ART_NODE256* n256 = (ART_NODE256*)art_create_node(NODE256);
    if (!n256) return NULL;
    n256->base.type = NODE256;
    n256->base.num_of_child = 0;

    for (USHORT i = 0; i < count; i++) {
        UCHAR idx = (UCHAR)(start_key + i);
        UCHAR kbuf[2] = { 'k', (UCHAR)(idx) };
        ART_LEAF* lf = make_leaf(kbuf, 2, /*value*/ idx);
        if (!lf) {
            for (USHORT j = 0; j < 256; j++) {
                ART_NODE* ch = n256->children[j];
                if (ch && IS_LEAF(ch)) {
                    ART_LEAF* l2 = LEAF_RAW(ch);
                    free_leaf(&l2);
                    n256->children[j] = NULL;
                }
            }
            ExFreePool2(n256, ART_TAG, NULL, 0);
            return NULL;
        }
        if (out_leaves && i < out_leaves_cap) out_leaves[i] = lf;
        n256->children[idx] = (ART_NODE*)SET_LEAF(lf);
        n256->base.num_of_child++;
    }

    if (out_ref_saved) *out_ref_saved = (ART_NODE*)n256;
    return n256;
}

static VOID t_free_node256_and_leaf_children(ART_NODE256** pn256)
{
    if (!pn256 || !*pn256) return;
    ART_NODE256* n256 = *pn256;
    for (USHORT i = 0; i < 256; i++) {
        ART_NODE* ch = n256->children[i];
        if (ch && IS_LEAF(ch)) {
            ART_LEAF* lf = LEAF_RAW(ch);
            free_leaf(&lf);
            n256->children[i] = NULL;
        }
    }
    free_node((ART_NODE**)&n256);
    *pn256 = NULL;
}

static VOID t_free_node48_and_leaf_children(ART_NODE48** pn48)
{
    if (!pn48 || !*pn48) return;
    ART_NODE48* n48 = *pn48;
    for (USHORT i = 0; i < 48; i++) {
        ART_NODE* ch = n48->children[i];
        if (ch && IS_LEAF(ch)) {
            ART_LEAF* lf = LEAF_RAW(ch);
            free_leaf(&lf);
            n48->children[i] = NULL;
        }
    }
    free_node((ART_NODE**)&n48);
    *pn48 = NULL;
}

// ===============================================================
// Test 1: Guard checks (NULL node/ref)
// ===============================================================
BOOLEAN test_remove_child256_guards()
{
    TEST_START("remove_child256: guard checks");

    reset_mock_state();

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child256(NULL, NULL, 0);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node/ref rejected");
#pragma warning(pop)

    ART_NODE256* n256 = (ART_NODE256*)art_create_node(NODE256);
    TEST_ASSERT(n256 != NULL, "1-pre: allocate node256");
    n256->base.type = NODE256;

#pragma warning(push)
#pragma warning(disable: 6387)
    st = remove_child256(n256, NULL, 0);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref rejected");
#pragma warning(pop)

    free_node((ART_NODE**)&n256);

    TEST_END("remove_child256: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: Child not found (no change)
// ===============================================================
BOOLEAN test_remove_child256_child_not_found()
{
    TEST_START("remove_child256: child not found");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE256* n256 = t_make_node256_with_children_count(/*count*/ 3, /*start_key*/ 10, &ref, NULL, 0);
    TEST_ASSERT(n256 != NULL, "2-pre: created node256 with 3 children");

    USHORT before = n256->base.num_of_child;

    NTSTATUS st = remove_child256(n256, &ref, /*c*/ 1); // index 1 has no child
    TEST_ASSERT(st == STATUS_NOT_FOUND, "2.1: returns STATUS_NOT_FOUND");
    TEST_ASSERT(n256->base.num_of_child == before, "2.2: num_of_child unchanged");
    TEST_ASSERT((ART_NODE256*)ref == n256, "2.3: ref unchanged");

    t_free_node256_and_leaf_children(&n256);

    TEST_END("remove_child256: child not found");
    return TRUE;
}

// ===============================================================
// Test 3: Remove a child without resize (count stays > 37)
// ===============================================================
BOOLEAN test_remove_child256_no_resize()
{
    TEST_START("remove_child256: remove child, no resize");

    reset_mock_state();

    ART_NODE* ref = NULL;
    // Use 39 children so after remove , 38 (>37) , no shrink
    ART_NODE256* n256 = t_make_node256_with_children_count(/*count*/ 39, /*start_key*/ 50, &ref, NULL, 0);
    TEST_ASSERT(n256 != NULL, "3-pre: created node256 with 39 children");
    TEST_ASSERT(n256->base.num_of_child == 39, "3-pre: count=39");

    UCHAR key_to_remove = 60;
    TEST_ASSERT(n256->children[key_to_remove] != NULL, "3-pre: child exists at 60");

    NTSTATUS st = remove_child256(n256, &ref, key_to_remove);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: removal succeeds");
    TEST_ASSERT(n256->children[key_to_remove] == NULL, "3.2: slot cleared");
    TEST_ASSERT(n256->base.num_of_child == 38, "3.3: num_of_child decremented");
    TEST_ASSERT((ART_NODE256*)ref == n256, "3.4: ref unchanged (no resize)");

    t_free_node256_and_leaf_children(&n256);

    TEST_END("remove_child256: remove child, no resize");
    return TRUE;
}

// ===============================================================
// Test 4: Resize to NODE48 on threshold (38 -> remove 1 -> 37)
// ===============================================================
BOOLEAN test_remove_child256_resize_to_48_success()
{
    TEST_START("remove_child256: resize to NODE48 at threshold");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[64]; t_zero(leaves, sizeof(leaves));

    ART_NODE256* n256 = t_make_node256_with_children_count(/*count*/ 38, /*start_key*/ 50,
        &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n256 != NULL, "4-pre: created node256 with 38 children");
    TEST_ASSERT(n256->base.num_of_child == 38, "4-pre: count=38");

    UCHAR remove_index = 60;
    TEST_ASSERT(n256->children[remove_index] != NULL, "4-pre: child exists at 60");

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = remove_child256(n256, &ref, remove_index);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: call succeeds and resizes");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "4.2: old NODE256 freed exactly once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "4.3: freed with ART_TAG");

    // After resize, ref must point to a NODE48
    TEST_ASSERT(ref != NULL, "4.4: ref updated");
    ART_NODE48* n48 = (ART_NODE48*)ref;
    TEST_ASSERT(n48->base.type == NODE48, "4.5: new node type is NODE48");

    // new node must have 37 children (all original except the removed one)
    TEST_ASSERT(n48->base.num_of_child == 37, "4.6: new node child count = 37");

    // Validate mappings for the 50..87 range, minus the removed index
    USHORT seen = 0;
    for (USHORT i = 0; i < 256; i++) {
        if (i == remove_index) {
            TEST_ASSERT(n48->child_index[i] == 0, "4.7: removed index has zero mapping");
            continue;
        }
        if (i >= 50 && i <= 87) {
            UCHAR pos1 = n48->child_index[i];
            TEST_ASSERT(pos1 != 0, "4.8: remaining key has non-zero index");
            UCHAR child_pos = (UCHAR)(pos1 - 1);
            TEST_ASSERT(child_pos < 48, "4.9: mapped position within [0..47]");
            TEST_ASSERT(n48->children[child_pos] != NULL, "4.10: child present at mapped position");
            seen++;
        }
        else {
            TEST_ASSERT(n48->child_index[i] == 0, "4.11: unrelated indices unmapped");
        }
    }
    TEST_ASSERT(seen == 37, "4.12: exactly 37 children migrated");

    // Cleanup
    t_free_node48_and_leaf_children(&n48);
    ref = NULL;

    TEST_END("remove_child256: resize to NODE48 at threshold");
    return TRUE;
}

// ===============================================================
// Test 5: Allocation failure during shrink , full rollback
// ===============================================================
BOOLEAN test_remove_child256_alloc_failure_rollback()
{
    TEST_START("remove_child256: allocation failure , rollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE256* n256 = t_make_node256_with_children_count(/*count*/ 38, /*start_key*/ 80, &ref, NULL, 0);
    TEST_ASSERT(n256 != NULL, "5-pre: created node256 with 38 children");

    UCHAR remove_index = 90;
    TEST_ASSERT(n256->children[remove_index] != NULL, "5-pre: child exists at 90");
    USHORT before_count = n256->base.num_of_child;

    // Make the *next* allocation fail (art_create_node inside shrink path)
    FI_ON_NEXT_ALLOC();

    NTSTATUS st = remove_child256(n256, &ref, remove_index);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "5.1: returns INSUFFICIENT_RESOURCES");
    TEST_ASSERT(n256->base.num_of_child == before_count, "5.2: num_of_child restored");
    TEST_ASSERT(n256->children[remove_index] != NULL, "5.3: removed child pointer restored");
    TEST_ASSERT((ART_NODE256*)ref == n256, "5.4: ref unchanged (no publish)");

    // Cleanup
    FI_OFF();
    t_free_node256_and_leaf_children(&n256);

    TEST_END("remove_child256: allocation failure , rollback");
    return TRUE;
}

// ===============================================================
// (Optional) Test 6: Document branches that require fault injection
// ===============================================================
BOOLEAN test_remove_child256_branches_documentation()
{
    TEST_START("remove_child256: branches needing FI (documentation)");

    // Note:
    // - copy_header failure path would require hooking or fault injection on copy_header;
    //   we intentionally skip it here. Allocation failure rollback (Test 5) already
    //   exercises the rollback machinery meaningfully.
    LOG_MSG("[INFO] Skipping copy_header-failure path (would require FI/hook).\n");

    TEST_END("remove_child256: branches needing FI (documentation)");
    return TRUE;
}

// ===============================================================
// Test X: Resize path with count mismatch , DATA_ERROR + full rollback
// Purpose:
//  - Simulate a corrupted NODE256 where base.num_of_child claims one more
//    child than actually present (there is an extra unexpected NULL).
//  - After removing a valid child (triggering shrink), repack finds fewer
//    live children (pos < node->base.num_of_child). The function should
//    detect mismatch, return STATUS_DATA_ERROR, and rollback the removal
//    (restoring the child pointer and num_of_child).
// ===============================================================
BOOLEAN test_remove_child256_resize_count_mismatch_rollback()
{
    TEST_START("remove_child256: resize , count mismatch , rollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    // Start with 38 children , removal makes it 37 and triggers shrink.
    ART_NODE256* n256 = t_make_node256_with_children_count(/*count*/ 38, /*start_key*/ 10, &ref, NULL, 0);
    TEST_ASSERT(n256 != NULL, "X-pre: created node256 with 38 children");

    // Corrupt the structure slightly: null-out one *different* child
    // so the actual live count is 37 already, although metadata says 38.
    UCHAR extra_null_index = 25;            // must be within [10..47]
    TEST_ASSERT(n256->children[extra_null_index] != NULL, "X-pre: extra child initially present");
    ART_NODE* extra_saved = n256->children[extra_null_index];
    n256->children[extra_null_index] = NULL;    // silent corruption: one less live child

    // Now remove another valid child , metadata will say 37 after removal,
    // but live children will be 36. That should trigger count-mismatch rollback.
    UCHAR remove_index = 15;
    TEST_ASSERT(n256->children[remove_index] != NULL, "X-pre: removable child exists");
    USHORT before_count = n256->base.num_of_child;
    ART_NODE* removed_saved = n256->children[remove_index];

    NTSTATUS st = remove_child256(n256, &ref, remove_index);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "X.1: must detect count mismatch and return DATA_ERROR");

    // Verify rollback: ref unchanged, child pointer restored, count restored.
    TEST_ASSERT((ART_NODE256*)ref == n256, "X.2: ref unchanged on rollback");
    TEST_ASSERT(n256->children[remove_index] == removed_saved, "X.3: removed child restored");
    TEST_ASSERT(n256->base.num_of_child == before_count, "X.4: num_of_child restored");

    // Put back the previously corrupted slot to cleanly free
    n256->children[extra_null_index] = extra_saved;

    // Cleanup
    t_free_node256_and_leaf_children(&n256);

    TEST_END("remove_child256: resize , count mismatch , rollback");
    return TRUE;
}

// ===============================================================
// Suite Runner
// ===============================================================
NTSTATUS run_all_remove_child256_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting remove_child256() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child256_guards())                             all = FALSE; // 1
    if (!test_remove_child256_child_not_found())                    all = FALSE; // 2
    if (!test_remove_child256_no_resize())                          all = FALSE; // 3
    if (!test_remove_child256_resize_to_48_success())               all = FALSE; // 4
    if (!test_remove_child256_alloc_failure_rollback())             all = FALSE; // 5
    if (!test_remove_child256_branches_documentation())             all = FALSE; // 6 (doc/skip)
    if (!test_remove_child256_resize_count_mismatch_rollback())     all = FALSE; // X

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL remove_child256() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME remove_child256() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
