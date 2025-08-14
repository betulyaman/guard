#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child16(_In_ ART_NODE16* node,
    _Inout_ ART_NODE** ref,
    _In_ ART_NODE** leaf);

// ---- Fault-injection convenience (same style as other suites) ----
#ifndef FI_ON_NEXT_ALLOC
#define FI_ON_NEXT_ALLOC() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, g_alloc_call_count)
#endif
#ifndef FI_OFF
#define FI_OFF() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0)
#endif

// ---------------- tiny local helpers (no CRT) ----------------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE16* t_make_node16_with_children_count(USHORT count,
    UCHAR first_key,
    ART_NODE** out_ref_base,
    ART_LEAF** out_leaves,
    USHORT out_leaves_cap)
{
    // Build NODE16 with "count" children on ascending keys:
    // keys[i] = first_key + i, children[i] = leaf("k", key)
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    if (!n16) return NULL;

    n16->base.type = NODE16;
    n16->base.num_of_child = 0;
    t_zero(n16->keys, sizeof(n16->keys));
    t_zero(n16->children, sizeof(n16->children));

    for (USHORT i = 0; i < count && i < 16; i++) {
        UCHAR k = (UCHAR)(first_key + i);
        UCHAR kbuf[2] = { 'k', k };
        ART_LEAF* lf = make_leaf(kbuf, 2, /*value*/ k);
        if (!lf) {
            // best-effort cleanup
            for (USHORT j = 0; j < 16; j++) {
                ART_NODE* ch = n16->children[j];
                if (ch && IS_LEAF(ch)) {
                    ART_LEAF* l2 = LEAF_RAW(ch);
                    free_leaf(&l2);
                    n16->children[j] = NULL;
                }
            }
            free_node((ART_NODE**)&n16);
            return NULL;
        }
        if (out_leaves && i < out_leaves_cap) out_leaves[i] = lf;

        n16->keys[i] = k;
        n16->children[i] = (ART_NODE*)SET_LEAF(lf);
        n16->base.num_of_child++;
    }

    if (out_ref_base) *out_ref_base = (ART_NODE*)n16;
    return n16;
}

static VOID t_free_node16_and_leaf_children(ART_NODE16** pn16)
{
    if (!pn16 || !*pn16) return;
    ART_NODE16* n16 = *pn16;
    for (USHORT i = 0; i < 16; i++) {
        ART_NODE* ch = n16->children[i];
        if (ch && IS_LEAF(ch)) {
            ART_LEAF* lf = LEAF_RAW(ch);
            free_leaf(&lf);
            n16->children[i] = NULL;
        }
    }
    free_node((ART_NODE**)pn16); // sets *pn16 = NULL
}

static VOID t_free_node4_and_leaf_children(ART_NODE4** pn4)
{
    if (!pn4 || !*pn4) return;
    ART_NODE4* n4 = *pn4;
    for (USHORT i = 0; i < 4; i++) {
        ART_NODE* ch = n4->children[i];
        if (ch && IS_LEAF(ch)) {
            ART_LEAF* lf = LEAF_RAW(ch);
            free_leaf(&lf);
            n4->children[i] = NULL;
        }
    }
    free_node((ART_NODE**)pn4);
}

// After a removal-without-resize, free all remaining leaf children plus the removed one
static VOID t_cleanup_after_remove_no_resize(ART_NODE16** pn16,
    ART_LEAF* removed_leaf_optional)
{
    if (removed_leaf_optional) {
        free_leaf(&removed_leaf_optional);
    }
    t_free_node16_and_leaf_children(pn16);
}

// ===============================================================
// Test 1: Guard checks
// ===============================================================
BOOLEAN test_remove_child16_guards()
{
    TEST_START("remove_child16: guard checks");

    reset_mock_state();
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child16(NULL, NULL, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node/ref/leaf rejected");

    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    TEST_ASSERT(n16 != NULL, "1-pre: created NODE16");
    n16->base.type = NODE16;

    ART_NODE* ref = (ART_NODE*)n16;
    st = remove_child16(n16, NULL, &n16->children[0]);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref rejected");

    st = remove_child16(n16, &ref, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: NULL leaf rejected");

    free_node((ART_NODE**)&n16);

    TEST_END("remove_child16: guard checks");
    return TRUE;
}

// ===============================================================
// Test 1b: Wrong node type
// ===============================================================
BOOLEAN test_remove_child16_wrong_type()
{
    TEST_START("remove_child16: wrong type");

    reset_mock_state();

    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    TEST_ASSERT(n16 != NULL, "1b-pre: created NODE16");
    n16->base.type = NODE48; // corrupt type

    ART_NODE* ref = (ART_NODE*)n16;
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child16(n16, &ref, &n16->children[0]);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1b.1: non-NODE16 rejected");
    TEST_ASSERT(ref == (ART_NODE*)n16, "1b.2: ref unchanged on reject");

    free_node((ART_NODE**)&n16);

    TEST_END("remove_child16: wrong type");
    return TRUE;
}

// ===============================================================
// Test 2: Invalid position
//   - leaf pointer outside children array , STATUS_INVALID_PARAMETER
//   - leaf pointer inside array but >= num_of_child , STATUS_INVALID_PARAMETER
// ===============================================================
BOOLEAN test_remove_child16_invalid_position()
{
    TEST_START("remove_child16: invalid position");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 5, /*first_key*/ 10, &ref, NULL, 0);
    TEST_ASSERT(n16 != NULL, "2-pre: created NODE16(5)");

    // 2.1: pointer outside the array (one-past-the-end)
    ART_NODE** bad_leaf_ptr = &n16->children[RTL_NUMBER_OF(n16->children)];
    NTSTATUS st = remove_child16(n16, &ref, bad_leaf_ptr);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: leaf ptr outside children array , invalid parameter");

    // 2.2: pointer inside array but pos >= num_of_child (pos=10, count=5)
    ART_NODE** inside_ptr = &n16->children[10];   // within array, but index 10
    st = remove_child16(n16, &ref, inside_ptr);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.2: pos >= child count , invalid parameter");

    t_free_node16_and_leaf_children(&n16);

    TEST_END("remove_child16: invalid position");
    return TRUE;
}

// ===============================================================
// Test 3: Child at position is NULL , STATUS_NOT_FOUND
// ===============================================================
BOOLEAN test_remove_child16_child_null()
{
    TEST_START("remove_child16: mapped but child NULL");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 6, /*first_key*/ 30, &ref, NULL, 0);
    TEST_ASSERT(n16 != NULL, "3-pre: created NODE16(6)");

    // Invalidate a slot that would be in-range
    n16->children[2] = NULL;

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[2]);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "3.1: returns STATUS_NOT_FOUND");

    t_free_node16_and_leaf_children(&n16);

    TEST_END("remove_child16: mapped but child NULL");
    return TRUE;
}

// ===============================================================
// Test 4: Remove from middle (no resize) — verify shift and count
// ===============================================================
BOOLEAN test_remove_child16_remove_middle_no_resize()
{
    TEST_START("remove_child16: remove middle (no resize)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[16]; t_zero(leaves, sizeof(leaves));
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 6, /*first_key*/ 40, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n16 != NULL, "4-pre: created NODE16(6)");

    // Remove position 2 (third element)
    USHORT before_count = n16->base.num_of_child; // 6
    ART_NODE* removed_child = n16->children[2];

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[2]);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: call succeeds");
    TEST_ASSERT(((ART_NODE16*)ref) == n16, "4.2: no resize, ref unchanged");
    TEST_ASSERT(n16->base.num_of_child == before_count - 1, "4.3: count decremented to 5");

    // Verify shift of keys: 40,41,43,44,45
    TEST_ASSERT(n16->keys[0] == 40, "4.4: key[0] ok");
    TEST_ASSERT(n16->keys[1] == 41, "4.5: key[1] ok");
    TEST_ASSERT(n16->keys[2] == 43, "4.6: key[2] shifted");
    TEST_ASSERT(n16->keys[3] == 44, "4.7: key[3] shifted");
    TEST_ASSERT(n16->keys[4] == 45, "4.8: key[4] shifted");

    // Verify child shift
    TEST_ASSERT(n16->children[2] != NULL, "4.9: child[2] now previous child[3]");
    TEST_ASSERT(n16->children[3] != NULL, "4.10: child[3] now previous child[4]");
    TEST_ASSERT(n16->children[4] != NULL, "4.11: child[4] now previous child[5]");

    // Cleanup
    ART_LEAF* removed_leaf = NULL;
    if (removed_child && IS_LEAF(removed_child)) {
        removed_leaf = LEAF_RAW(removed_child);
    }
    t_cleanup_after_remove_no_resize(&n16, removed_leaf);

    TEST_END("remove_child16: remove middle (no resize)");
    return TRUE;
}

// ===============================================================
// Test 5: Remove first (no resize) — verify shift
// ===============================================================
BOOLEAN test_remove_child16_remove_first_no_resize()
{
    TEST_START("remove_child16: remove first (no resize)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[16]; t_zero(leaves, sizeof(leaves));
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 5, /*first_key*/ 60, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n16 != NULL, "5-pre: created NODE16(5)");

    ART_NODE* removed_child = n16->children[0];

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: success");
    TEST_ASSERT(n16->base.num_of_child == 4, "5.2: count decremented to 4");

    // keys become 61,62,63,64
    TEST_ASSERT(n16->keys[0] == 61 && n16->keys[3] == 64, "5.3: keys shifted left");

    ART_LEAF* removed_leaf = IS_LEAF(removed_child) ? LEAF_RAW(removed_child) : NULL;
    t_cleanup_after_remove_no_resize(&n16, removed_leaf);

    TEST_END("remove_child16: remove first (no resize)");
    return TRUE;
}

// ===============================================================
// Test 6: Remove last (no resize) — verify tail cut
// ===============================================================
BOOLEAN test_remove_child16_remove_last_no_resize()
{
    TEST_START("remove_child16: remove last (no resize)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[16]; t_zero(leaves, sizeof(leaves));
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 5, /*first_key*/ 80, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n16 != NULL, "6-pre: created NODE16(5)");

    ART_NODE* removed_child = n16->children[4];

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[4]);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: success");
    TEST_ASSERT(n16->base.num_of_child == 4, "6.2: count decremented to 4");

    // keys remain 80..83
    TEST_ASSERT(n16->keys[0] == 80 && n16->keys[3] == 83, "6.3: tail cut ok (no mid shift)");

    ART_LEAF* removed_leaf = IS_LEAF(removed_child) ? LEAF_RAW(removed_child) : NULL;
    t_cleanup_after_remove_no_resize(&n16, removed_leaf);

    TEST_END("remove_child16: remove last (no resize)");
    return TRUE;
}

// ===============================================================
// Test 7: Threshold , resize to NODE4
// Start with 4 children; remove one , 3 , resize. Validate:
//  - ref becomes NODE4
//  - num_of_child == 3
//  - keys/children copied in order
//  - old NODE16 freed
// ===============================================================
BOOLEAN test_remove_child16_resize_to_node4()
{
    TEST_START("remove_child16: resize to NODE4 on threshold");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[16]; t_zero(leaves, sizeof(leaves));
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 4, /*first_key*/ 100, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n16 != NULL, "7-pre: created NODE16(4)");

    ULONG frees_before = g_free_call_count;

    // Remove second item (pos=1), remaining should be 3 , resize path
    ART_NODE* removed_child = n16->children[1];
    NTSTATUS st = remove_child16(n16, &ref, &n16->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: success");

    // After resize, ref should be a NODE4
    ART_NODE4* n4 = (ART_NODE4*)ref;
    TEST_ASSERT(n4 != NULL && n4->base.type == NODE4, "7.2: ref updated to NODE4");
    TEST_ASSERT(n4->base.num_of_child == 3, "7.3: new node child count = 3");

    // keys must be ascending and equal to original (except removed 101)
    TEST_ASSERT(n4->keys[0] == 100, "7.4: first key ok");
    TEST_ASSERT(n4->keys[1] == 102, "7.5: second key ok (101 removed)");
    TEST_ASSERT(n4->keys[2] == 103, "7.6: third key ok");

    // Children should be non-NULL
    TEST_ASSERT(n4->children[0] != NULL &&
        n4->children[1] != NULL &&
        n4->children[2] != NULL, "7.7: children present");

    // Old NODE16 must be freed once
    TEST_ASSERT(g_free_call_count == frees_before + 1, "7.8: old NODE16 freed once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "7.9: freed with ART_TAG");

    // Cleanup: free remaining leaves from NODE4, then node4 itself, plus the removed leaf
    if (removed_child && IS_LEAF(removed_child)) {
        ART_LEAF* rem = LEAF_RAW(removed_child);
        free_leaf(&rem);
    }
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child16: resize to NODE4 on threshold");
    return TRUE;
}

// ===============================================================
// Test 8: Allocation failure during shrink (FI)full rollback
// ===============================================================
BOOLEAN test_remove_child16_alloc_failure_on_shrink()
{
    TEST_START("remove_child16: alloc failure on shrinkrollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = t_make_node16_with_children_count(/*count*/ 4, /*first_key*/ 10, &ref, NULL, 0);
    TEST_ASSERT(n16 != NULL, "8-pre: created NODE16(4)");

    // snap state
    UCHAR  pos = 1;
    ART_NODE* saved_child = n16->children[pos];
    UCHAR  saved_key[4]; for (int i = 0; i < 4; ++i) saved_key[i] = n16->keys[i];
    USHORT saved_count = n16->base.num_of_child;

    // make next allocation fail (NODE4 allocation)
    FI_ON_NEXT_ALLOC();

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[pos]);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "8.1: art_create_node(NODE4) failsINSUFFICIENT_RESOURCES");

    // verify rollback: node intact, ref unchanged
    TEST_ASSERT((ART_NODE16*)ref == n16, "8.2: ref unchanged");
    TEST_ASSERT(n16->base.num_of_child == saved_count, "8.3: count unchanged");
    TEST_ASSERT(n16->children[pos] == saved_child, "8.4: removed slot restored");
    for (int i = 0; i < 4; ++i) TEST_ASSERT(n16->keys[i] == saved_key[i], "8.5: keys unchanged");

    // cleanup
    FI_OFF();
    t_free_node16_and_leaf_children(&n16);

    TEST_END("remove_child16: alloc failure on shrinkrollback");
    return TRUE;
}

// ===============================================================
// Test 9: FI-only branches (documented) — copy_header failure
// (requires dedicated hook; kept as documentation like other suites)
// ===============================================================
BOOLEAN test_remove_child16_fi_only_branches_documented()
{
    TEST_START("remove_child16: FI-only branches (documented)");
    LOG_MSG("[INFO] copy_header failure requires FI to simulate.\n");
    TEST_END("remove_child16: FI-only branches (documented)");
    return TRUE;
}

// ===============================================================
// Test 10: Removing the only child of NODE16 -> publish NULL and free
// ===============================================================
BOOLEAN test_remove_child16_remove_last_child_publish_null()
{
    TEST_START("remove_child16: remove last child -> publish NULL");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    TEST_ASSERT(n16 != NULL, "10-pre: NODE16 alloc");
    n16->base.type = NODE16;
    n16->base.num_of_child = 1;
    RtlZeroMemory(n16->keys, sizeof(n16->keys));
    RtlZeroMemory(n16->children, sizeof(n16->children));

    // add single leaf child at slot 0
    UCHAR kb[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kb, 1, 0x33);
    TEST_ASSERT(lf != NULL, "10-pre: leaf alloc");
    n16->keys[0] = 0x61; // 'a'
    n16->children[0] = (ART_NODE*)SET_LEAF(lf);
    ref = (ART_NODE*)n16;

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "10.1: removal succeeds");
    TEST_ASSERT(ref == NULL, "10.2: ref published as NULL");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "10.3: NODE16 freed exactly once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "10.4: freed with ART_TAG");

    // leaf is detached, free it manually
    if (lf) free_leaf(&lf);

    TEST_END("remove_child16: remove last child -> publish NULL");
    return TRUE;
}

// ===============================================================
// Test 11 : copy_header failure during NODE16->NODE4 shrink -> rollback
// ===============================================================
BOOLEAN test_remove_child16_copy_header_failure_rollback()
{
    TEST_START("remove_child16 (DEBUG): copy_header failure -> rollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    TEST_ASSERT(n16 != NULL, "11-pre: NODE16 alloc");
    n16->base.type = NODE16;
    n16->base.num_of_child = 4;
    RtlZeroMemory(n16->keys, sizeof(n16->keys));
    RtlZeroMemory(n16->children, sizeof(n16->children));

    // keys = 10,11,12,13 with 4 leaves
    for (USHORT i = 0; i < 4; ++i) {
        UCHAR keyb = (UCHAR)(10 + i);
        UCHAR kbuf[2] = { 'k', keyb };
        ART_LEAF* lf = make_leaf(kbuf, 2, keyb);
        TEST_ASSERT(lf != NULL, "11-pre: leaf alloc");
        n16->keys[i] = keyb;
        n16->children[i] = (ART_NODE*)SET_LEAF(lf);
    }
    ref = (ART_NODE*)n16;

    // Snapshot for rollback (removing slot 1)
    USHORT before_count = n16->base.num_of_child;
    UCHAR  saved_keys[4]; for (int i = 0; i < 4; i++) saved_keys[i] = n16->keys[i];
    ART_NODE* saved_child = n16->children[1];

    // Force copy_header to fail once inside shrink path
    g_copy_header_fail_once_flag = 1;
    g_copy_header_fail_status = STATUS_DATA_ERROR;

    NTSTATUS st = remove_child16(n16, &ref, &n16->children[1]);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "11.1: STATUS_DATA_ERROR bubbled");

    // Verify rollback
    TEST_ASSERT((ART_NODE16*)ref == n16, "11.2: ref unchanged");
    TEST_ASSERT(n16->base.num_of_child == before_count, "11.3: count restored");
    for (int i = 0; i < 4; i++) TEST_ASSERT(n16->keys[i] == saved_keys[i], "11.4: keys restored");
    TEST_ASSERT(n16->children[1] == saved_child, "11.5: child pointer restored");

    // Cleanup
    t_free_node16_and_leaf_children(&n16);
    TEST_END("remove_child16 (DEBUG): copy_header failure -> rollback");
    return TRUE;
}


// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_remove_child16_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting remove_child16() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child16_guards())                          all = FALSE; // 1
    if (!test_remove_child16_wrong_type())                      all = FALSE; // 1b
    if (!test_remove_child16_invalid_position())                all = FALSE; // 2
    if (!test_remove_child16_child_null())                      all = FALSE; // 3
    if (!test_remove_child16_remove_middle_no_resize())         all = FALSE; // 4
    if (!test_remove_child16_remove_first_no_resize())          all = FALSE; // 5
    if (!test_remove_child16_remove_last_no_resize())           all = FALSE; // 6
    if (!test_remove_child16_resize_to_node4())                 all = FALSE; // 7
    if (!test_remove_child16_alloc_failure_on_shrink())         all = FALSE; // 8
    if (!test_remove_child16_fi_only_branches_documented())     all = FALSE; // 9 (doc)
    if (!test_remove_child16_remove_last_child_publish_null())  all = FALSE; // 10
    if (!test_remove_child16_copy_header_failure_rollback())    all = FALSE; // 11


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL remove_child16() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME remove_child16() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif