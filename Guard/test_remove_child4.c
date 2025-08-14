#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _Inout_ ART_NODE** remove_slot);

STATIC INLINE USHORT t_u16_add_clamp(USHORT a, USHORT b)
{
    ULONG s = (ULONG)a + (ULONG)b;
    return (USHORT)(s > 0xFFFF ? 0xFFFF : s); // clamp to MAXUSHORT
}

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
            // no grandchildren in these tests
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
    n4->base.type = NODE4;
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
// Test 1b: Wrong type
// ===============================================================
BOOLEAN test_remove_child4_wrong_type()
{
    TEST_START("remove_child4: wrong node type");

    reset_mock_state();

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4, "1b-pre: alloc NODE4");
    n4->base.type = NODE16; // wrong
    ART_NODE* ref = (ART_NODE*)n4;

#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1b.1: non-NODE4 rejected");
    TEST_ASSERT(ref == (ART_NODE*)n4, "1b.2: ref unchanged on reject");

    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: wrong node type");
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

    ART_NODE** bogus = (ART_NODE**)&ref; // not a slot address
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

    USHORT before = n4->base.num_of_child; // 3
    ART_NODE* removed = n4->children[1];

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: success");
    TEST_ASSERT(((ART_NODE4*)ref) == n4, "4.2: no collapse, ref unchanged");
    TEST_ASSERT(n4->base.num_of_child == before - 1, "4.3: count decremented to 2");

    // Keys were 40,41,42 -> now 40,42
    TEST_ASSERT(n4->keys[0] == 40, "4.4: key[0] ok");
    TEST_ASSERT(n4->keys[1] == 42, "4.5: key[1] shifted");

    // Children shifted left
    TEST_ASSERT(n4->children[0] != NULL, "4.6: child[0] present");
    TEST_ASSERT(n4->children[1] != NULL, "4.7: child[1] shifted");

    // Cleanup
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

    ART_NODE* removed = n4->children[0];
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: success");

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
// Test 8: Collapse to internal + prefix merge
// ===============================================================
BOOLEAN test_remove_child4_collapse_to_internal_prefix_merge()
{
    TEST_START("remove_child4: collapse to internal + prefix merge");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x21 /* '!' */, &ref, &internal);
    TEST_ASSERT(n4 != NULL && internal != NULL, "8-pre: NODE4 with internal child");

    // Parent prefix: "ABC"
    static const UCHAR PARENT_PFX[] = { 'A','B','C' };
    n4->base.prefix_length = (USHORT)RTL_NUMBER_OF(PARENT_PFX);
    for (USHORT i = 0; i < n4->base.prefix_length && i < (USHORT)MAX_PREFIX_LENGTH; ++i) {
        n4->base.prefix[i] = PARENT_PFX[i];
    }

    // Add a second child (leaf) so we can collapse
    UCHAR kbuf[2] = { 'x','y' };
    ART_LEAF* lf = make_leaf(kbuf, 2, 0x55);
    TEST_ASSERT(lf != NULL, "8-pre: created leaf");
    n4->keys[1] = 0x7E; // '~'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    // Child prefix: "child"
    static const UCHAR CHILD_PFX[] = { 'c','h','i','l','d' };
    ART_NODE* child_node = internal;
    child_node->prefix_length = (USHORT)RTL_NUMBER_OF(CHILD_PFX);
    for (USHORT i = 0; i < child_node->prefix_length && i < (USHORT)MAX_PREFIX_LENGTH; ++i) {
        child_node->prefix[i] = CHILD_PFX[i];
    }

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: success");
    TEST_ASSERT(ref == internal, "8.2: ref now equals internal node");

    // Logical merged length: 3 + 1 + 5 = 9
    TEST_ASSERT(child_node->prefix_length == 9, "8.3: merged logical prefix length is 9");

    static const UCHAR EXPECTED_BYTES[9] = { 'A','B','C','!','c','h','i','l','d' };
    USHORT to_check = 9;
    if (to_check > (USHORT)MAX_PREFIX_LENGTH) to_check = (USHORT)MAX_PREFIX_LENGTH;
    for (USHORT i = 0; i < to_check; ++i) {
        TEST_ASSERT(child_node->prefix[i] == EXPECTED_BYTES[i], "8.4: merged prefix content OK");
    }

    TEST_ASSERT(g_free_call_count == frees_before + 1, "8.5: old NODE4 freed once");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "8.6: freed with ART_TAG");

    // Cleanup
    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: collapse to internal + prefix merge");
    return TRUE;
}

// ===============================================================
// Test 9: Collapse path defensive error when remaining child is NULL
// ===============================================================
BOOLEAN test_remove_child4_collapse_remaining_child_null()
{
    TEST_START("remove_child4: collapse path with NULL remaining child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "9-pre: created NODE4");

    // num_of_child = 2, child[0]=leaf, child[1]=NULL -> remove child[0] ⇒ count=1, remaining NULL
    n4->base.type = NODE4;
    n4->base.num_of_child = 2;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    UCHAR kb[1] = { 'z' };
    ART_LEAF* lf = make_leaf(kb, 1, 0xAA);
    TEST_ASSERT(lf != NULL, "9-pre: made leaf");
    n4->keys[0] = 1;
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);
    n4->keys[1] = 2;
    n4->children[1] = NULL;

    ref = (ART_NODE*)n4;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(st == STATUS_DATA_ERROR, "9.1: remaining child NULL -> DATA_ERROR");

    if (lf) free_leaf(&lf);
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: collapse path with NULL remaining child");
    return TRUE;
}

// 10.3 — collapse: logical length preserved with USHORT clamp,
// stored bytes truncated to MAX_PREFIX_LENGTH
BOOLEAN test_remove_child4_prefix_truncation_on_collapse()
{
    TEST_START("remove_child4: prefix truncation on collapse (logical preserved, bytes capped)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;

    // Build NODE4 with one internal child at key 0x42 ('B')
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x42, &ref, &internal);
    TEST_ASSERT(n4 && internal, "10.3-pre: NODE4 + internal child created");

    // Parent logical prefix is larger than MAX_PREFIX_LENGTH so that capping is observable
    const USHORT parent_logical = (USHORT)(MAX_PREFIX_LENGTH + 12);
    n4->base.prefix_length = parent_logical;
    for (USHORT i = 0; i < (USHORT)MAX_PREFIX_LENGTH; ++i) {
        n4->base.prefix[i] = (UCHAR)('P'); // parent fragment
    }

    // Add a second child (a leaf) so that removal triggers collapse into 'internal'
    UCHAR kbuf[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kbuf, 1, 0x55);
    TEST_ASSERT(lf, "10.3-pre: leaf alloc ok");

    // Put leaf at slot 1 (any non-zero slot is fine for this test)
    n4->keys[1] = 0x7A;                       // 'z'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    // Child internal prefix
    const USHORT child_len = 20;
    internal->prefix_length = child_len;
    for (USHORT i = 0; i < (USHORT)min((USHORT)MAX_PREFIX_LENGTH, child_len); ++i) {
        internal->prefix[i] = (UCHAR)('C'); // child fragment
    }

    // Remove the leaf → collapse should merge: parent.prefix + edge + child.prefix into 'internal'
    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "10.3.1: collapse returns success");
    TEST_ASSERT(ref == internal, "10.3.2: ref now points to internal after collapse");

    // Expected logical length with USHORT saturation
    USHORT expected_logical = t_u16_add_clamp(t_u16_add_clamp(parent_logical, 1), child_len);
    TEST_ASSERT(internal->prefix_length == expected_logical,
        "10.3.3: merged logical length preserved with USHORT clamp");

    // Also verify stored bytes are truncated to MAX_PREFIX_LENGTH
    // Construct the expected first MAX_PREFIX_LENGTH bytes: parent 'P's, then edge 0x7A, then child 'C's
    UCHAR expect[MAX_PREFIX_LENGTH];
    USHORT w = 0;

    // Copy parent fragment (only stored fragment exists; logical may exceed)
    USHORT parent_copy = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, parent_logical);
    for (USHORT i = 0; i < parent_copy && w < (USHORT)MAX_PREFIX_LENGTH; ++i) {
        expect[w++] = 'P';
    }

    // Edge byte if room remains
    if (w < (USHORT)MAX_PREFIX_LENGTH) {
        expect[w++] = 0x7A; // 'z'
    }

    // Child fragment
    for (USHORT i = 0; i < child_len && w < (USHORT)MAX_PREFIX_LENGTH; ++i) {
        expect[w++] = 'C';
    }

    // Compare stored bytes prefix
    TEST_ASSERT(RtlCompareMemory(internal->prefix, expect, (SIZE_T)w) == w,
        "10.3.4: stored prefix bytes match expected truncated sequence");

    // Cleanup
    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: prefix truncation on collapse (logical preserved, bytes capped)");
    return TRUE;
}

// ===============================================================
// Test 11: Removing the only child -> node freed and *ref == NULL
// ===============================================================
BOOLEAN test_remove_child4_remove_last_child_clears_ref()
{
    TEST_START("remove_child4: remove last child -> ref=NULL");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "11-pre: NODE4 alloc");
    n4->base.type = NODE4;
    n4->base.num_of_child = 1;

    // add single leaf child
    UCHAR kb[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kb, 1, 0x11);
    TEST_ASSERT(lf != NULL, "11-pre: leaf alloc");
    n4->keys[0] = 0x61; // 'a'
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);
    ref = (ART_NODE*)n4;

    ULONG frees_before = g_free_call_count;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
    TEST_ASSERT(NT_SUCCESS(st), "11.1: removal succeeds");
    TEST_ASSERT(ref == NULL, "11.2: ref cleared");
    TEST_ASSERT(g_free_call_count == frees_before + 1, "11.3: NODE4 freed exactly once");

    free_leaf(&lf);

    TEST_END("remove_child4: remove last child -> ref=NULL");
    return TRUE;
}

// ===============================================================
// EXTRA 1: Merge-only edge when both prefixes empty
// ===============================================================
BOOLEAN test_remove_child4_merge_only_edge_when_prefixes_empty()
{
    TEST_START("remove_child4: merge-only edge when prefixes empty");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x2A /* '*' */, &ref, &internal);
    TEST_ASSERT(n4 && internal, "E1-pre: NODE4 + internal");

    n4->base.prefix_length = 0;

    // Add a second child (leaf) to collapse
    UCHAR kbuf[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kbuf, 1, 0x01);
    TEST_ASSERT(lf, "E1-pre: leaf alloc");
    n4->keys[1] = 0x7A; // 'z'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    internal->prefix_length = 0;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "E1.1: collapse success");
    TEST_ASSERT(ref == internal, "E1.2: ref == internal");

    TEST_ASSERT(internal->prefix_length == 1, "E1.3: merged logical length == 1");
    TEST_ASSERT(internal->prefix[0] == 0x2A, "E1.4: merged first byte == '*'");

    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: merge-only edge when prefixes empty");
    return TRUE;
}

// ===============================================================
// EXTRA 2: Extended logical length beyond MAX_PREFIX_LENGTH
// ===============================================================
BOOLEAN test_remove_child4_merge_extended_length_beyond_cap()
{
    TEST_START("remove_child4: extended logical length beyond MAX_PREFIX_LENGTH");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x21 /* '!' */, &ref, &internal);
    TEST_ASSERT(n4 && internal, "E2-pre: NODE4 + internal");

    const USHORT parent_logical = (USHORT)(MAX_PREFIX_LENGTH + 50);
    n4->base.prefix_length = parent_logical;
    for (USHORT i = 0; i < (USHORT)MAX_PREFIX_LENGTH; ++i)
        n4->base.prefix[i] = (UCHAR)('A' + (i % 26));

    UCHAR kbuf[1] = { 'y' };
    ART_LEAF* lf = make_leaf(kbuf, 1, 0x02);
    TEST_ASSERT(lf, "E2-pre: leaf alloc");
    n4->keys[1] = 0x7E; // '~'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    internal->prefix_length = 8;
    for (USHORT i = 0; i < 8; ++i) internal->prefix[i] = 'c';

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "E2.1: collapse success");
    TEST_ASSERT(ref == internal, "E2.2: ref == internal");

    TEST_ASSERT(internal->prefix_length == (USHORT)(parent_logical + 1 + 8),
        "E2.3: merged logical length preserved (>MAX_PREFIX_LENGTH)");

    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: extended logical length beyond MAX_PREFIX_LENGTH");
    return TRUE;
}

// ===============================================================
// EXTRA 3: USHORT clamp of logical prefix length
// ===============================================================
BOOLEAN test_remove_child4_merge_ushort_clamp()
{
    TEST_START("remove_child4: USHORT clamp of logical prefix length");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*key*/ 0x23 /* '#' */, &ref, &internal);
    TEST_ASSERT(n4 && internal, "E3-pre: NODE4 + internal");

    const USHORT parent_logical = 65530;
    n4->base.prefix_length = parent_logical;
    for (USHORT i = 0; i < (USHORT)MAX_PREFIX_LENGTH; ++i)
        n4->base.prefix[i] = 0xAB;

    UCHAR kbuf[1] = { 'q' };
    ART_LEAF* lf = make_leaf(kbuf, 1, 0x03);
    TEST_ASSERT(lf, "E3-pre: leaf alloc");
    n4->keys[1] = 0x61; // 'a'
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    internal->prefix_length = 10;
    for (USHORT i = 0; i < 10; ++i) internal->prefix[i] = 0xCD;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "E3.1: collapse success");
    TEST_ASSERT(ref == internal, "E3.2: ref == internal");
    TEST_ASSERT(internal->prefix_length == 0xFFFF, "E3.3: logical length clamped to MAXUSHORT");

    if (ref && !IS_LEAF(ref)) { ART_NODE* tmp = ref; free_node(&tmp); }
    if (lf) free_leaf(&lf);

    TEST_END("remove_child4: USHORT clamp of logical prefix length");
    return TRUE;
}

// ===============================================================
// EXTRA 4: Tail clearing after shift (keys[last]=0, children[last]=NULL)
// ===============================================================
BOOLEAN test_remove_child4_shift_clears_tail()
{
    TEST_START("remove_child4: tail slot cleared after shift");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaves[4] = { 0 };
    ART_NODE4* n4 = t_make_node4_with_children_count(/*count*/ 4, /*first_key*/ 10, &ref, leaves, RTL_NUMBER_OF(leaves));
    TEST_ASSERT(n4, "E4-pre: NODE4(4)");

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "E4.1: success");
    TEST_ASSERT(n4->base.num_of_child == 3, "E4.2: count=3");
    TEST_ASSERT(n4->children[3] == NULL, "E4.3: last child slot cleared");
    TEST_ASSERT(n4->keys[3] == 0, "E4.4: last key slot cleared");

    for (USHORT i = 0; i < 4; i++) {
        if (leaves[i]) { ART_LEAF* lf = leaves[i]; free_leaf(&lf); }
    }
    t_free_node4_and_leaf_children(&n4);

    TEST_END("remove_child4: tail slot cleared after shift");
    return TRUE;
}

// ===============================================================
// EXTRA 5: Invalid child count guards (0 and >4)
// ===============================================================
BOOLEAN test_remove_child4_invalid_child_counts()
{
    TEST_START("remove_child4: invalid child counts");

    reset_mock_state();

    // count=0
    {
        ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
        TEST_ASSERT(n4, "E5-pre: NODE4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 0;
        ART_NODE* ref = (ART_NODE*)n4;
        NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
        TEST_ASSERT(st == STATUS_DATA_ERROR, "E5.1: count=0 => DATA_ERROR");
        t_free_node4_and_leaf_children(&n4);
    }

    // count=5 (>4) — corrupted state
    {
        ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
        TEST_ASSERT(n4, "E5-pre: NODE4 alloc #2");
        n4->base.type = NODE4;
        n4->base.num_of_child = 5;
        ART_NODE* ref = (ART_NODE*)n4;
        NTSTATUS st = remove_child4(n4, &ref, &n4->children[0]);
        TEST_ASSERT(st == STATUS_DATA_ERROR, "E5.2: count>4 => DATA_ERROR");
        t_free_node4_and_leaf_children(&n4);
    }

    TEST_END("remove_child4: invalid child counts");
    return TRUE;
}

BOOLEAN test_remove_child4_ref_mismatch_debug()
{
    TEST_START("remove_child4: DEBUG guard *ref != node");

    reset_mock_state();

    ART_NODE4* n4_a = (ART_NODE4*)art_create_node(NODE4);
    ART_NODE4* n4_b = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4_a && n4_b, "ref mismatch pre: alloc");

    n4_a->base.type = NODE4; n4_a->base.num_of_child = 1;
    n4_b->base.type = NODE4; n4_b->base.num_of_child = 0;

    UCHAR kb[1] = { 'x' };
    ART_LEAF* lf = make_leaf(kb, 1, 0x11);
    TEST_ASSERT(lf, "leaf alloc");
    n4_a->keys[0] = 'a';
    n4_a->children[0] = (ART_NODE*)SET_LEAF(lf);

    ART_NODE* ref = (ART_NODE*)n4_b; // yanlış ref

    NTSTATUS st = remove_child4(n4_a, &ref, &n4_a->children[0]);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "DEBUG guard triggers");

    // cleanup
    free_leaf(&lf);
    t_free_node4_and_leaf_children(&n4_a);
    t_free_node4_and_leaf_children(&n4_b);

    TEST_END("remove_child4: DEBUG guard *ref != node");
    return TRUE;
}

BOOLEAN test_remove_child4_slot_beyond_count()
{
    TEST_START("remove_child4: slot beyond num_of_child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = t_make_node4_with_children_count(2, 10, &ref, NULL, 0);
    TEST_ASSERT(n4, "pre: NODE4(2)");

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[3]); // 3 geçerli alan, ama count=2
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "slot beyond count rejected");

    t_free_node4_and_leaf_children(&n4);
    TEST_END("remove_child4: slot beyond num_of_child");
    return TRUE;
}

BOOLEAN test_remove_child4_parent_full_child_empty_truncation()
{
    TEST_START("remove_child4: parent full, child empty, edge truncation");

    reset_mock_state();

    ART_NODE* ref = NULL; ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(0x41 /*'A'*/, &ref, &internal);
    TEST_ASSERT(n4 && internal, "pre");

    n4->base.prefix_length = MAX_PREFIX_LENGTH;
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; i++) n4->base.prefix[i] = 'P';

    internal->prefix_length = 0;

    // ikinci çocuk: leaf (silinecek)
    UCHAR k[1] = { 'x' }; ART_LEAF* lf = make_leaf(k, 1, 1); TEST_ASSERT(lf, "leaf");
    n4->keys[1] = 0x7A; n4->children[1] = (ART_NODE*)SET_LEAF(lf); n4->base.num_of_child = 2;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "success");
    TEST_ASSERT(ref == internal, "ref=internal");
    TEST_ASSERT(internal->prefix_length == (USHORT)(MAX_PREFIX_LENGTH + 1),
        "logical len parent+edge");

    // Saklanan baytlar: MAX_PREFIX_LENGTH dolu olduğu için edge sığmaz; dizi tamamen 'P' kalmalı
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; i++) {
        TEST_ASSERT(internal->prefix[i] == 'P', "stored bytes all P");
    }

    ART_NODE* tmp = ref; free_node(&tmp); free_leaf(&lf);
    TEST_END("parent full, child empty, edge truncation");
    return TRUE;
}

BOOLEAN test_remove_child4_remove_internal_middle_no_collapse()
{
    TEST_START("remove_child4: remove internal in the middle (no collapse)");

    reset_mock_state();

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4, "pre: n4");
    n4->base.type = NODE4; n4->base.num_of_child = 0;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    // left leaf
    UCHAR ka[1] = { 'a' }; ART_LEAF* la = make_leaf(ka, 1, 1);
    // middle internal
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    // right leaf
    UCHAR kc[1] = { 'c' }; ART_LEAF* lc = make_leaf(kc, 1, 3);

    TEST_ASSERT(la && n16 && lc, "allocs ok");

    n4->keys[0] = 'a'; n4->children[0] = (ART_NODE*)SET_LEAF(la);
    n4->keys[1] = 'b'; n4->children[1] = (ART_NODE*)n16;
    n4->keys[2] = 'c'; n4->children[2] = (ART_NODE*)SET_LEAF(lc);
    n4->base.num_of_child = 3;

    ART_NODE* ref = (ART_NODE*)n4;

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]); // internal’ı sil
    TEST_ASSERT(NT_SUCCESS(st), "success");
    TEST_ASSERT(((ART_NODE4*)ref) == n4, "no collapse");
    TEST_ASSERT(n4->base.num_of_child == 2, "count=2");
    TEST_ASSERT(n4->keys[0] == 'a' && n4->keys[1] == 'c', "keys shifted");
    TEST_ASSERT(n4->children[0] && n4->children[1], "children shifted");

    // cleanup: kalan 2 yaprağı serbest bırak
    ART_LEAF* l0 = LEAF_RAW(n4->children[0]);
    ART_LEAF* l1 = LEAF_RAW(n4->children[1]);
    free_leaf(&l0); free_leaf(&l1);
    // silinen internal test tarafından explicit free edilmeli (API serbest bırakmıyor)
    ART_NODE* tmp = (ART_NODE*)n16; free_node(&tmp);
    t_free_node4_and_leaf_children((ART_NODE4**)&ref);

    TEST_END("remove internal middle (no collapse)");
    return TRUE;
}

BOOLEAN test_remove_child4_collapse_edge_key_correctness()
{
    TEST_START("remove_child4: collapse edge byte correctness");

    reset_mock_state();

    ART_NODE* ref = NULL; ART_NODE* internal = NULL;
    ART_NODE4* n4 = t_make_node4_with_internal_child(/*edge*/ 0x33 /*'3'*/, &ref, &internal);
    TEST_ASSERT(n4 && internal, "pre");

    // ikinci çocuk: leaf
    UCHAR kbuf[1] = { 'x' }; ART_LEAF* lf = make_leaf(kbuf, 1, 0x42); TEST_ASSERT(lf, "leaf");
    n4->keys[1] = 0x7A; // 'z' -> silinecek olan leaf
    n4->children[1] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 2;

    // parent prefix = "PQ"
    n4->base.prefix_length = 2; n4->base.prefix[0] = 'P'; n4->base.prefix[1] = 'Q';

    // child prefix = "r"
    internal->prefix_length = 1; internal->prefix[0] = 'r';

    NTSTATUS st = remove_child4(n4, &ref, &n4->children[1]);
    TEST_ASSERT(NT_SUCCESS(st), "success");
    TEST_ASSERT(ref == internal, "ref=internal");
    TEST_ASSERT(internal->prefix_length == 4, "2+1+1");
    TEST_ASSERT(internal->prefix[0] == 'P' && internal->prefix[1] == 'Q' &&
        internal->prefix[2] == 0x33 /*'3'*/ && internal->prefix[3] == 'r',
        "merged bytes P,Q,edge('3'),r");

    ART_NODE* tmp = ref; free_node(&tmp);
    free_leaf(&lf);

    TEST_END("collapse edge byte correctness");
    return TRUE;
}


// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_remove_child4_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting remove_child4() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child4_guards())                           all = FALSE; // 1
    if (!test_remove_child4_wrong_type())                       all = FALSE; // 1b
    if (!test_remove_child4_invalid_leaf_ptr())                 all = FALSE; // 2
    if (!test_remove_child4_child_null())                       all = FALSE; // 3
    if (!test_remove_child4_remove_middle_no_collapse())        all = FALSE; // 4
    if (!test_remove_child4_remove_first_no_collapse())         all = FALSE; // 5
    if (!test_remove_child4_remove_last_no_collapse())          all = FALSE; // 6
    if (!test_remove_child4_collapse_to_leaf())                 all = FALSE; // 7
    if (!test_remove_child4_collapse_to_internal_prefix_merge())all = FALSE; // 8
    if (!test_remove_child4_collapse_remaining_child_null())    all = FALSE; // 9
    if (!test_remove_child4_prefix_truncation_on_collapse())    all = FALSE; // 10
    if (!test_remove_child4_remove_last_child_clears_ref())     all = FALSE; // 11
    if (!test_remove_child4_merge_only_edge_when_prefixes_empty())  all = FALSE; // E1
    if (!test_remove_child4_merge_extended_length_beyond_cap())     all = FALSE; // E2
    if (!test_remove_child4_merge_ushort_clamp())                   all = FALSE; // E3
    if (!test_remove_child4_shift_clears_tail())                    all = FALSE; // E4
    if (!test_remove_child4_invalid_child_counts())                 all = FALSE; // E5
    if (!test_remove_child4_ref_mismatch_debug())                 all = FALSE; 
    if (!test_remove_child4_slot_beyond_count())                  all = FALSE; 
    if (!test_remove_child4_remove_internal_middle_no_collapse()) all = FALSE; 
    if (!test_remove_child4_collapse_edge_key_correctness())      all = FALSE; 
    if (!test_remove_child4_parent_full_child_empty_truncation()) all = FALSE; 


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL remove_child4() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME remove_child4() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif