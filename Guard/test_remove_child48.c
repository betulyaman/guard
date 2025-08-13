#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child48(_In_ ART_NODE48* node,
    _Inout_ ART_NODE** ref,
    _In_ UCHAR c);

// ---- Fault-injection convenience (same style as other suites) ----
#ifndef FI_ON_NEXT_ALLOC
#define FI_ON_NEXT_ALLOC() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, g_alloc_call_count)
#endif
#ifndef FI_OFF
#define FI_OFF() \
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0)
#endif

// ------------ tiny local helpers (no CRT) -------------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE48* t_make_node48_with_children_count(USHORT count, UCHAR first_key,
    ART_NODE** out_ref_base,
    ART_LEAF** out_leaves,
    USHORT out_leaves_cap)
{
    // Build a NODE48 with "count" children on key bytes:
    //   keys = first_key, first_key+1, ..., first_key+count-1
    // Sequentially mapped to children[0..count-1] (child_index[key] = pos+1).
    ART_NODE48* n48 = (ART_NODE48*)art_create_node(NODE48);
    if (!n48) return NULL;

    n48->base.type = NODE48;
    n48->base.num_of_child = 0;
    t_zero(n48->child_index, sizeof(n48->child_index));
    t_zero(n48->children, sizeof(n48->children));

    for (USHORT i = 0; i < count; i++) {
        UCHAR keyb = (UCHAR)(first_key + i);
        UCHAR pos = (UCHAR)i;

        UCHAR kbuf[2] = { 'k', keyb };
        ART_LEAF* lf = make_leaf(kbuf, 2, /*value*/ keyb);
        if (!lf) {
            // best-effort cleanup
            for (USHORT j = 0; j < 48; j++) {
                ART_NODE* ch = n48->children[j];
                if (ch && IS_LEAF(ch)) {
                    ART_LEAF* l2 = LEAF_RAW(ch);
                    free_leaf(&l2);
                    n48->children[j] = NULL;
                }
            }
            free_node((ART_NODE**)&n48);
            return NULL;
        }
        if (out_leaves && i < out_leaves_cap) out_leaves[i] = lf;

        n48->children[pos] = (ART_NODE*)SET_LEAF(lf);
        n48->child_index[keyb] = (UCHAR)(pos + 1);
        n48->base.num_of_child++;
    }

    if (out_ref_base) *out_ref_base = (ART_NODE*)n48;
    return n48;
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
    free_node((ART_NODE**)pn48); // sets *pn48 = NULL inside
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
    free_node((ART_NODE**)pn16);
}

// ===============================================================
// Test 1: Guard checks
// ===============================================================
BOOLEAN test_remove_child48_guards()
{
    TEST_START("remove_child48: guard checks");

    reset_mock_state();

    NTSTATUS st = remove_child48(NULL, NULL, 0);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL node+ref rejected");

    ART_NODE48* n48 = (ART_NODE48*)art_create_node(NODE48);
    TEST_ASSERT(n48 != NULL, "1-pre: created NODE48");
    n48->base.type = NODE48;

    st = remove_child48(n48, NULL, 0);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL ref rejected");

    free_node((ART_NODE**)&n48);

    TEST_END("remove_child48: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: Not found cases (and no leaks while simulating corruption)
// ===============================================================
BOOLEAN test_remove_child48_not_found_cases()
{
    TEST_START("remove_child48: not found cases");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE48* n48 = t_make_node48_with_children_count(/*count*/ 3, /*first_key*/ 20, &ref, NULL, 0);
    TEST_ASSERT(n48 != NULL, "2-pre: make NODE48");

    // 2.1 key not present (child_index[c] == 0)
    NTSTATUS st = remove_child48(n48, &ref, /*c*/ 5);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "2.1: absent key , STATUS_NOT_FOUND");

    // 2.2 corrupt index > 48 (simulate)
    n48->child_index[7] = 49; // invalid
    st = remove_child48(n48, &ref, /*c*/ 7);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "2.2: pos > 48 , STATUS_NOT_FOUND");
    n48->child_index[7] = 0;

    // 2.3 mapped but NULL child (simulate) — save & restore to avoid leak
    // Use a fresh mapping that points to slot 0, then NULL that slot temporarily.
    UCHAR saved_pos1b = n48->child_index[20];          // original child at slot 0 (pos1b=1)
    TEST_ASSERT(saved_pos1b == 1, "2-pre: key 20 at slot 0");
    ART_NODE* saved_ch0 = n48->children[0];
    TEST_ASSERT(saved_ch0 != NULL, "2-pre: slot 0 child exists");

    n48->child_index[8] = 1;       // fake mapping -> slot 0
    n48->children[0] = NULL;       // inconsistent mapping
    st = remove_child48(n48, &ref, /*c*/ 8);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "2.3: mapped but child NULL , STATUS_NOT_FOUND");

    // restore to prevent leak and leave original mapping intact
    n48->children[0] = saved_ch0;
    n48->child_index[8] = 0;

    // cleanup
    t_free_node48_and_leaf_children(&n48);

    TEST_END("remove_child48: not found cases");
    return TRUE;
}

// ===============================================================
// Test 3: Remove child without resize (no threshold hit)
// start with 14 children; remove one , 13 -> no resize
// ===============================================================
BOOLEAN test_remove_child48_remove_no_resize()
{
    TEST_START("remove_child48: remove child without resize");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE48* n48 = t_make_node48_with_children_count(/*count*/ 14, /*first_key*/ 50, &ref, NULL, 0);
    TEST_ASSERT(n48 != NULL, "3-pre: make NODE48(14)");

    USHORT before = n48->base.num_of_child;
    UCHAR to_remove = 55; // exists (50..63)
    UCHAR saved_pos = n48->child_index[to_remove];
    TEST_ASSERT(saved_pos > 0, "3-pre: key exists");

    NTSTATUS st = remove_child48(n48, &ref, to_remove);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: success");
    TEST_ASSERT(n48->base.num_of_child == before - 1, "3.2: count decremented to 13");
    TEST_ASSERT(n48->child_index[to_remove] == 0, "3.3: child_index cleared");
    TEST_ASSERT(n48->children[saved_pos - 1] == NULL, "3.4: child slot cleared");
    TEST_ASSERT(((ART_NODE48*)ref) == n48, "3.5: no resize => ref unchanged");

    // sanity: other keys still mapped
    for (UCHAR k = 50; k < 64; k++) {
        if (k == to_remove) continue;
        TEST_ASSERT(n48->child_index[k] != 0, "3.6: other keys intact");
    }

    // cleanup
    t_free_node48_and_leaf_children(&n48);

    TEST_END("remove_child48: remove child without resize");
    return TRUE;
}

// ===============================================================
// Test 4: Underflow , resize to NODE16 (13 , remove 1 , 12)
// Validate: ref becomes NODE16, mapping order by key ascending,
// child count == 12, old NODE48 freed exactly once.
// ===============================================================
BOOLEAN test_remove_child48_resize_to_node16()
{
    TEST_START("remove_child48: resize to NODE16 on threshold");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[48];
    t_zero(leaves, sizeof(leaves));

    ART_NODE48* n48 = t_make_node48_with_children_count(/*count*/ 13, /*first_key*/ 100,
        &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n48 != NULL, "4-pre: make NODE48(13)");

    ULONG frees_before = g_free_call_count;

    // remove one that exists , count becomes 12 , resize path
    UCHAR rem = 105;
    TEST_ASSERT(n48->child_index[rem] != 0, "4-pre: removable key exists");

    NTSTATUS st = remove_child48(n48, &ref, rem);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: success");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "4.2: old NODE48 freed once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "4.3: freed with ART_TAG");
    TEST_ASSERT(ref != NULL, "4.4: ref updated to new node");

    ART_NODE16* n16 = (ART_NODE16*)ref;
    TEST_ASSERT(n16->base.type == NODE16, "4.5: new node is NODE16");
    TEST_ASSERT(n16->base.num_of_child == 12, "4.6: 12 children after resize");

    // Validate keys[] are in ascending key byte order,
    // and each children[i] maps to the exact original child (except removed).
    UCHAR expected_count = 0;
    UCHAR last_key = 0;
    for (USHORT i = 0; i < n16->base.num_of_child; i++) {
        UCHAR k = n16->keys[i];
        if (i > 0) {
            TEST_ASSERT(k > last_key, "4.7: keys[] strictly ascending");
        }
        last_key = k;

        TEST_ASSERT(n16->children[i] != NULL, "4.8: child present");
        // original keys were 100..112 except 'rem'
        TEST_ASSERT(k >= 100 && k <= 112 && k != rem, "4.9: key within expected range and not removed");
        expected_count++;
    }
    TEST_ASSERT(expected_count == 12, "4.10: exactly 12 migrated");

    // cleanup: free leaf children from NODE16 and then the node
    t_free_node16_and_leaf_children(&n16);
    ref = NULL;

    TEST_END("remove_child48: resize to NODE16 on threshold");
    return TRUE;
}

// ===============================================================
// Test 5: Allocation failure during shrink , full rollback
// ===============================================================
BOOLEAN test_remove_child48_alloc_failure_rollback()
{
    TEST_START("remove_child48: allocation failure , rollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    // 13 children , removing 1 triggers shrink to NODE16
    ART_NODE48* n48 = t_make_node48_with_children_count(/*count*/ 13, /*first_key*/ 70,
        &ref, NULL, 0);
    TEST_ASSERT(n48 != NULL, "5-pre: make NODE48(13)");

    UCHAR rem = 75;
    TEST_ASSERT(n48->child_index[rem] != 0, "5-pre: removable key exists");

    // Snapshot state for rollback checks
    USHORT before_count = n48->base.num_of_child;
    UCHAR  pos1b = n48->child_index[rem];
    ART_NODE* ptr_before = n48->children[pos1b ? (pos1b - 1) : 0];

    // Fail the *next* allocation (art_create_node in shrink path)
    FI_ON_NEXT_ALLOC();

    NTSTATUS st = remove_child48(n48, &ref, rem);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "5.1: returns INSUFFICIENT_RESOURCES");

    // Rollback verified
    TEST_ASSERT(n48->base.num_of_child == before_count, "5.2: count restored");
    TEST_ASSERT(n48->child_index[rem] == pos1b, "5.3: index restored");
    TEST_ASSERT(n48->children[pos1b - 1] == ptr_before, "5.4: child pointer restored");
    TEST_ASSERT((ART_NODE48*)ref == n48, "5.5: ref unchanged (no publish)");

    // Cleanup
    FI_OFF();
    t_free_node48_and_leaf_children(&n48);

    TEST_END("remove_child48: allocation failure , rollback");
    return TRUE;
}

// ===============================================================
// Test 6: Corrupt mapping during repack (mapped , NULL child) , rollback
// (save+restore the corrupted slot to avoid leaks)
// ===============================================================
BOOLEAN test_remove_child48_repack_null_child_rollback()
{
    TEST_START("remove_child48: repack mapped,NULL child , rollback");

    reset_mock_state();

    ART_NODE* ref = NULL;
    // 13 children , removing 1 triggers shrink/repack
    ART_NODE48* n48 = t_make_node48_with_children_count(/*count*/ 13, /*first_key*/ 100,
        &ref, NULL, 0);
    TEST_ASSERT(n48 != NULL, "6-pre: make NODE48(13)");

    // Choose a key to remove (to trigger shrink)
    UCHAR rem = 105;
    TEST_ASSERT(n48->child_index[rem] != 0, "6-pre: removable key exists");

    // Corrupt another mapped key so that child_index[x] > 0 but children[pos-1] == NULL
    UCHAR corrupt_key = 110;
    TEST_ASSERT(corrupt_key != rem, "6-pre: pick different key to corrupt");
    UCHAR corrupt_pos1b = n48->child_index[corrupt_key];
    TEST_ASSERT(corrupt_pos1b != 0, "6-pre: corrupt_key is mapped");

    ART_NODE* corrupt_saved = n48->children[corrupt_pos1b - 1]; // save to avoid leak
    TEST_ASSERT(corrupt_saved != NULL, "6-pre: corrupt slot child exists");
    n48->children[corrupt_pos1b - 1] = NULL; // introduce corruption for repack loop

    // Snapshot for rollback verification of 'rem'
    USHORT before_count = n48->base.num_of_child;
    UCHAR  rem_pos1b = n48->child_index[rem];
    ART_NODE* rem_ptr = n48->children[rem_pos1b - 1];

    NTSTATUS st = remove_child48(n48, &ref, rem);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "6.1: repack detects corruption , STATUS_DATA_ERROR");

    // Full rollback expected for 'rem'
    TEST_ASSERT(n48->base.num_of_child == before_count, "6.2: count restored");
    TEST_ASSERT(n48->child_index[rem] == rem_pos1b, "6.3: index for 'rem' restored");
    TEST_ASSERT(n48->children[rem_pos1b - 1] == rem_ptr, "6.4: child pointer for 'rem' restored");
    TEST_ASSERT((ART_NODE48*)ref == n48, "6.5: ref unchanged");

    // Restore the intentionally corrupted slot so cleanup can free it
    n48->children[corrupt_pos1b - 1] = corrupt_saved;

    // cleanup
    t_free_node48_and_leaf_children(&n48);

    TEST_END("remove_child48: repack mapped,NULL child , rollback");
    return TRUE;
}

// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_remove_child48_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting remove_child48() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child48_guards())                         all = FALSE; // 1
    if (!test_remove_child48_not_found_cases())                all = FALSE; // 2
    if (!test_remove_child48_remove_no_resize())               all = FALSE; // 3
    if (!test_remove_child48_resize_to_node16())               all = FALSE; // 4
    if (!test_remove_child48_alloc_failure_rollback())         all = FALSE; // 5
    if (!test_remove_child48_repack_null_child_rollback())     all = FALSE; // 6

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL remove_child48() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME remove_child48() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
