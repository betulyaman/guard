#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child4(_In_ ART_NODE4* node,
    _Inout_ ART_NODE** ref,
    _In_ ART_NODE** leaf);

// ---------- tiny local helpers (no CRT) ----------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* t_make_node4_with_children_count(USHORT count,
    UCHAR first_key,
    ART_NODE** out_ref_base,
    ART_LEAF** out_leaves,
    USHORT out_leaves_cap)
{
    // Create NODE4, then fill up to 4 children with ascending keys
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    for (USHORT i = 0; i < count && i < 4; i++) {
        UCHAR k = (UCHAR)(first_key + i);
        UCHAR kbuf[2] = { 'k', k };
        ART_LEAF* lf = make_leaf(kbuf, 2, /*value*/ k);
        if (!lf) {
            // best-effort cleanup
            for (USHORT j = 0; j < 4; j++) {
                ART_NODE* ch = n4->children[j];
                if (ch && IS_LEAF(ch)) {
                    ART_LEAF* l2 = LEAF_RAW(ch);
                    free_leaf(&l2);
                    n4->children[j] = NULL;
                }
            }
            free_node((ART_NODE**)&n4);
            return NULL;
        }
        if (out_leaves && i < out_leaves_cap) out_leaves[i] = lf;

        n4->keys[i] = k;
        n4->children[i] = (ART_NODE*)SET_LEAF(lf);
        n4->base.num_of_child++;
    }

    if (out_ref_base) *out_ref_base = (ART_NODE*)n4;
    return n4;
}

static ART_NODE4* t_make_node4_with_internal_child(UCHAR key_for_internal,
    ART_NODE** out_ref_base,
    ART_NODE** out_internal)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    // Create an internal child (NODE16 here, empty)
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    if (!n16) { free_node((ART_NODE**)&n4); return NULL; }
    n16->base.type = NODE16;
    n16->base.num_of_child = 0;
    n16->base.prefix_length = 0;
    t_zero(n16->keys, sizeof(n16->keys));
    t_zero(n16->children, sizeof(n16->children));

    n4->keys[0] = key_for_internal;
    n4->children[0] = (ART_NODE*)n16;
    n4->base.num_of_child = 1;

    if (out_ref_base) *out_ref_base = (ART_NODE*)n4;
    if (out_internal) *out_internal = (ART_NODE*)n16;
    return n4;
}

// free helpers
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
        else if (ch && !IS_LEAF(ch)) {
            // if tests created an internal child, free it (no grandchildren in these tests)
            free_node(&ch);
        }
    }
    free_node((ART_NODE**)pn4); // sets *pn4 = NULL
}

// ===============================================================
// Test 1: Guard checks (NULL params)
// ===============================================================
BOOLEAN test_remove_child4_guards()
{
    TEST_START("remove_child4: guard checks");

    reset_mock_state();
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child4(NULL, NULL, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: rejects all NULL");

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "1-pre: created NODE4");
    ART_NODE* ref = (ART_NODE*)n4;

    st = remove_child4(n4, NULL, &n4->children[0]);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: rejects NULL ref");

    st = remove_child4(n4, &ref, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: rejects NULL leaf");

    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: Invalid leaf pointer (not matching any child slot)
// ===============================================================
BOOLEAN test_remove_child4_invalid_leaf_ptr()
{
    TEST_START("remove_child4: invalid leaf pointer");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 3, /*first_key*/ 10, &ref, NULL, 0);
    TEST_ASSERT(n4 != NULL, "2-pre: created NODE4(3)");

    // Pointer that is not equal to &node->children[i] for any i
    ART_NODE** bogus = (ART_NODE**)&ref; // arbitrary address not equal to a slot address

    NTSTATUS st = remove_child4(n4, &ref, bogus);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: invalid leaf pointer rejected");

    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: invalid leaf pointer");
    return TRUE;
}

// ===============================================================
// Test 3: Child at position is NULL , STATUS_NOT_FOUND
// ===============================================================
BOOLEAN test_remove_child4_child_null()
{
    TEST_START("remove_child4: mapped but NULL child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 3, /*first_key*/ 20, &ref, NULL, 0);
    TEST_ASSERT(n4 != NULL, "3-pre: created NODE4(3)");

    // Break invariant intentionally
    n4->children[1] = NULL;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "3.1: returns STATUS_NOT_FOUND on NULL child");

    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: mapped but NULL child");
    return TRUE;
}

// ===============================================================
// Test 4: Remove middle (no collapse) — verify shift and count
// ===============================================================
BOOLEAN test_remove_child4_remove_middle_no_collapse()
{
    TEST_START("remove_child4: remove middle (no collapse)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[4]; t_zero(leaves, sizeof(leaves));
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 3, /*first_key*/ 40, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n4 != NULL, "4-pre: created NODE4(3)");

    // Remove position 1 (middle)
    USHORT before = n4->base.num_of_child; // 3
    ART_NODE* removed = n4->children[1];

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: success");
    TEST_ASSERT(((ART_NODE4*)ref) == n4, "4.2: no collapse, ref unchanged");
    TEST_ASSERT(n4->base.num_of_child == before - 1, "4.3: count decremented to 2");

    // Keys were 40,41,42 , now 40,42
    TEST_ASSERT(n4->keys[0] == 40, "4.4: key[0] ok");
    TEST_ASSERT(n4->keys[1] == 42, "4.5: key[1] shifted (middle removed)");

    // Children shifted left
    TEST_ASSERT(n4->children[0] != NULL, "4.6: child[0] present");
    TEST_ASSERT(n4->children[1] != NULL, "4.7: child[1] shifted");

    // Cleanup: free removed leaf + remaining
    ART_LEAF* rlf = (removed && IS_LEAF(removed)) ? LEAF_RAW(removed) : NULL;
    if (rlf) free_leaf(&rlf);
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: remove middle (no collapse)");
    return TRUE;
}

// ===============================================================
// Test 5: Remove first (no collapse)
// ===============================================================
BOOLEAN test_remove_child4_remove_first_no_collapse()
{
    TEST_START("remove_child4: remove first (no collapse)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[4]; t_zero(leaves, sizeof(leaves));
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 3, /*first_key*/ 60, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n4 != NULL, "5-pre: created NODE4(3)");

    ART_NODE* removed = n4->children[0];
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: success");
    TEST_ASSERT(n4->base.num_of_child == 2, "5.2: count now 2");
    TEST_ASSERT(n4->keys[0] == 61 && n4->keys[1] == 62, "5.3: keys shifted left");

    ART_LEAF* rlf = (removed && IS_LEAF(removed)) ? LEAF_RAW(removed) : NULL;
    if (rlf) free_leaf(&rlf);
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: remove first (no collapse)");
    return TRUE;
}

// ===============================================================
// Test 6: Remove last (no collapse)
// ===============================================================
BOOLEAN test_remove_child4_remove_last_no_collapse()
{
    TEST_START("remove_child4: remove last (no collapse)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[4]; t_zero(leaves, sizeof(leaves));
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 3, /*first_key*/ 80, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n4 != NULL, "6-pre: created NODE4(3)");

    ART_NODE* removed = n4->children[2];
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[2]);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: success");
    TEST_ASSERT(n4->base.num_of_child == 2, "6.2: count now 2");
    TEST_ASSERT(n4->keys[0] == 80 && n4->keys[1] == 81, "6.3: tail removal ok");

    ART_LEAF* rlf = (removed && IS_LEAF(removed)) ? LEAF_RAW(removed) : NULL;
    if (rlf) free_leaf(&rlf);
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: remove last (no collapse)");
    return TRUE;
}

// ===============================================================
// Test 7: Collapse to remaining child = LEAF
//   Start with 2 children, remove one -> 1 left (leaf). `ref` becomes that leaf.
// ===============================================================
BOOLEAN test_remove_child4_collapse_to_leaf()
{
    TEST_START("remove_child4: collapse to remaining leaf");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[4]; t_zero(leaves, sizeof(leaves));
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 2, /*first_key*/ 100, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n4 != NULL, "7-pre: created NODE4(2)");

    ULONG frees_before = g_free_call_count;

    // Remove child at pos 0 , one child left at pos 0 (after shift)
    ART_NODE* removed = n4->children[0];
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: success");

    // After collapse, ref must be the remaining child (a leaf SET_LEAF)
    TEST_ASSERT(ref != NULL && IS_LEAF(ref), "7.2: ref now points to leaf");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "7.3: old NODE4 freed exactly once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "7.4: freed with ART_TAG");

    // Cleanup: free both leaves
    ART_LEAF* removed_leaf = (removed && IS_LEAF(removed)) ? LEAF_RAW(removed) : NULL;
    if (removed_leaf) free_leaf(&removed_leaf);
    if (ref && IS_LEAF(ref)) {
        ART_LEAF* remain = LEAF_RAW(ref);
        free_leaf(&remain);
    }

    TEST_END("remove_child4: collapse to remaining leaf");
    return TRUE;
}

// ===============================================================
// Test 8: Collapse to remaining child = INTERNAL NODE
//   Verify prefix merge: new_prefix = parent_prefix + key_byte + child_prefix (clamped to MAX_PREFIX_LENGTH)
// ===============================================================
BOOLEAN test_remove_child4_collapse_to_internal_prefix_merge()
{
    TEST_START("remove_child4: collapse to internal + prefix merge");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x21 /*'!'*/, &ref, &internal);
    TEST_ASSERT(n4 != NULL && internal != NULL, "8-pre: NODE4 with internal child");

    // Parent prefix: "ABC" (3 bytes)
    n4->base.prefix_length = 3;
    n4->base.prefix[0] = 'A';
    n4->base.prefix[1] = 'B';
    n4->base.prefix[2] = 'C';

    // Add a second child (leaf) to make count=2
    UCHAR kbuf[2] = { 'x', 'y' };
    ART_LEAF* lf = make_leaf(kbuf, 2, 0x55);
    TEST_ASSERT(lf != NULL, "8-pre: created leaf");
    n4->keys[1] = 0x7E; // '~'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    // Give child (internal) its own prefix: "child"
    ART_NODE* child_node = internal;
    child_node->prefix_length = 5;
    child_node->prefix[0] = 'c';
    child_node->prefix[1] = 'h';
    child_node->prefix[2] = 'i';
    child_node->prefix[3] = 'l';
    child_node->prefix[4] = 'd';

    ULONG frees_before = g_free_call_count;

    // Remove leaf at pos 1 so the remaining single child is the internal node at pos 0
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: success");

    // ref should now be the internal node
    TEST_ASSERT(ref == internal, "8.2: ref now equals internal node");

    // Verify merged prefix: "ABC" + '!' + "child" = "ABC!child" (9 bytes)
    TEST_ASSERT(child_node->prefix_length == 9, "8.3: merged prefix length is 9");

    TEST_ASSERT(child_node->prefix[0] == 'A' &&
        child_node->prefix[1] == 'B' &&
        child_node->prefix[2] == 'C' &&
        child_node->prefix[3] == '!' &&
        child_node->prefix[4] == 'c' &&
        child_node->prefix[5] == 'h' &&
        child_node->prefix[6] == 'i' &&
        child_node->prefix[7] == 'l' &&
        child_node->prefix[8] == 'd', "8.4: merged prefix content correct");

    TEST_ASSERT(g_free_call_count == frees_before + 1, "8.5: old NODE4 freed once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "8.6: freed with ART_TAG");

    // Cleanup: free internal node (no children) and removed leaf
    if (ref && !IS_LEAF(ref)) {
        ART_NODE* tmp = ref;
        free_node(&tmp);
    }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: collapse to internal + prefix merge");
    return TRUE;
}

// ===============================================================
// Test 9: Collapse path defensive error when remaining child is NULL
//   (violated invariant; crafted to hit STATUS_DATA_ERROR)
// ===============================================================
BOOLEAN test_remove_child4_collapse_remaining_child_null()
{
    TEST_START("remove_child4: collapse path with NULL remaining child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "9-pre: created NODE4");

    // Craft inconsistent state:
    // num_of_child = 2, children[0] = valid leaf, children[1] = NULL
    // Remove children[0] , shift brings NULL to [0], count=1 , collapse sees NULL child , STATUS_DATA_ERROR
    n4->base.type = NODE4;
    n4->base.num_of_child = 2;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    // child[0] = valid leaf
    UCHAR kb[1] = { 'z' };
    ART_LEAF* lf = make_leaf(kb, 1, 0xAA);
    TEST_ASSERT(lf != NULL, "9-pre: made leaf");
    n4->keys[0] = 1;
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);

    // child[1] = NULL (invariant break)
    n4->keys[1] = 2;
    n4->children[1] = NULL;

    ref = (ART_NODE*)n4;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "9.1: collapse with NULL remaining child , STATUS_DATA_ERROR");

    // Cleanup: free crafted leaf and node (node not freed by function on error)
    if (lf) free_leaf(&lf);
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: collapse path with NULL remaining child");
    return TRUE;
}

// ===============================================================
// Test 10: Collapse prefix truncation at MAX_PREFIX_LENGTH
//   parent_prefix (MAX_PREFIX_LENGTH-2) + key byte + child_prefix(10)
//   => final = MAX_PREFIX_LENGTH (truncated child prefix to available space)
// ===============================================================
BOOLEAN test_remove_child4_prefix_truncation_on_collapse()
{
    TEST_START("remove_child4: prefix truncation at MAX_PREFIX_LENGTH");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x33 /*'3'*/, &ref, &internal);
    TEST_ASSERT(n4 != NULL && internal != NULL, "10-pre: NODE4 with internal child");

    // Parent prefix of length MAX_PREFIX_LENGTH - 2
    USHORT plen = (USHORT)(MAX_PREFIX_LENGTH - 2);
    n4->base.prefix_length = plen;
    for (USHORT i = 0; i < plen; i++) n4->base.prefix[i] = (UCHAR)('A' + (i % 26));

    // Add a second leaf child so we can remove it and collapse onto internal
    UCHAR kbuf[2] = { 'p','q' };
    ART_LEAF* lf = make_leaf(kbuf, 2, 0xAB);
    TEST_ASSERT(lf != NULL, "10-pre: made leaf");
    n4->keys[1] = 0x7A; // 'z'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    // Child prefix set to 10 bytes of 'c'
    ART_NODE* child_node = internal;
    child_node->prefix_length = 10;
    for (USHORT i = 0; i < 10; i++) child_node->prefix[i] = 'c';

    ULONG frees_before = g_free_call_count;

    // Remove leaf at pos 1 , collapse
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "10.1: success");
    TEST_ASSERT(ref == internal, "10.2: ref now internal");

    // Merged length must be MAX_PREFIX_LENGTH:
    //  parent (MAX_PREFIX_LENGTH-2) + 1 key byte + min(child_prefix, 1) = MAX_PREFIX_LENGTH
    TEST_ASSERT(child_node->prefix_length == MAX_PREFIX_LENGTH,
        "10.3: merged prefix length clamped to MAX_PREFIX_LENGTH");

    TEST_ASSERT(g_free_call_count == frees_before + 1, "10.4: old NODE4 freed once");

    // Cleanup
    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: prefix truncation at MAX_PREFIX_LENGTH");
    return TRUE;
}

// ===============================================================
// Test: Removing the only child -> node freed and *ref == NULL
// ===============================================================
BOOLEAN test_remove_child4_remove_last_child_clears_ref()
{
    TEST_START("remove_child4: remove last child -> ref=NULL");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "pre: NODE4 alloc");
    n4->base.type = NODE4;
    n4->base.num_of_child = 1;

    // add single leaf child
    UCHAR kb[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kb, 1, 0x11);
    TEST_ASSERT(lf != NULL, "pre: leaf alloc");
    n4->keys[0] = 0x61; // 'a'
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);
    ref = (ART_NODE*)n4;

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "1: removal succeeds");
    TEST_ASSERT(ref == NULL, "2: ref cleared");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "3: NODE4 freed exactly once");

    // free remaining leaf
    free_leaf(&lf);

    TEST_END("remove_child4: remove last child -> ref=NULL");
    return TRUE;
}

// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_remove_child4_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting remove_child4() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child4_guards())                           all = FALSE; // 1
    if (!test_remove_child4_invalid_leaf_ptr())                 all = FALSE; // 2
    if (!test_remove_child4_child_null())                       all = FALSE; // 3
    if (!test_remove_child4_remove_middle_no_collapse())        all = FALSE; // 4
    if (!test_remove_child4_remove_first_no_collapse())         all = FALSE; // 5
    if (!test_remove_child4_remove_last_no_collapse())          all = FALSE; // 6
    if (!test_remove_child4_collapse_to_leaf())                 all = FALSE; // 7
    if (!test_remove_child4_collapse_to_internal_prefix_merge())all = FALSE; // 8
    if (!test_remove_child4_collapse_remaining_child_null())    all = FALSE; // 9
    if (!test_remove_child4_prefix_truncation_on_collapse())    all = FALSE; // 10
    if (!test_remove_child4_remove_last_child_clears_ref())     all = FALSE;

    DbgPrint("\n========================================\n");
    if (all) {
        DbgPrint("ALL remove_child4() TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME remove_child4() TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
