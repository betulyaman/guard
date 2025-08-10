#include "test_art.h"

// Function under test
STATIC NTSTATUS remove_child(_In_ ART_NODE* node, _Inout_ ART_NODE** ref,
    _In_ UCHAR c, _In_opt_ ART_NODE** leaf);

// ---------- small local helpers (kernel-safe, no CRT) ----------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* t_make_node4_with_two_leaves(ART_NODE** out_ref,
    ART_NODE*** out_leaf_slot0,
    ART_NODE*** out_leaf_slot1,
    ART_LEAF** out_l0,
    ART_LEAF** out_l1)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

    UCHAR k0[2] = { 'a','0' };
    UCHAR k1[2] = { 'a','1' };
    ART_LEAF* l0 = make_leaf(k0, 2, 0x10);
    ART_LEAF* l1 = make_leaf(k1, 2, 0x11);
    if (!l0 || !l1) {
        if (l0) free_leaf(&l0);
        if (l1) free_leaf(&l1);
        free_node((ART_NODE**)&n4);
        return NULL;
    }

    n4->keys[0] = 5;  n4->children[0] = (ART_NODE*)SET_LEAF(l0);
    n4->keys[1] = 9;  n4->children[1] = (ART_NODE*)SET_LEAF(l1);
    n4->base.num_of_child = 2;

    if (out_ref) *out_ref = (ART_NODE*)n4;
    if (out_leaf_slot0) *out_leaf_slot0 = &n4->children[0];
    if (out_leaf_slot1) *out_leaf_slot1 = &n4->children[1];
    if (out_l0) *out_l0 = l0;
    if (out_l1) *out_l1 = l1;
    return n4;
}

static ART_NODE16* t_make_node16_with_four_leaves(ART_NODE** out_ref,
    ART_NODE*** out_leaf_slot2 /*optional*/)
{
    ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
    if (!n16) return NULL;
    n16->base.type = NODE16;
    n16->base.num_of_child = 0;
    t_zero(n16->keys, sizeof(n16->keys));
    t_zero(n16->children, sizeof(n16->children));

    for (USHORT i = 0; i < 4; i++) {
        UCHAR kb[2] = { 'b', (UCHAR)('0' + i) };
        ART_LEAF* lf = make_leaf(kb, 2, 0x20 + i);
        if (!lf) {
            // cleanup any prior leaves
            for (USHORT j = 0; j < i; j++) {
                ART_NODE* ch = n16->children[j];
                if (IS_LEAF(ch)) {
                    ART_LEAF* l2 = LEAF_RAW(ch);
                    free_leaf(&l2);
                }
            }
            free_node((ART_NODE**)&n16);
            return NULL;
        }
        n16->keys[i] = (UCHAR)(10 + i);
        n16->children[i] = (ART_NODE*)SET_LEAF(lf);
        n16->base.num_of_child++;
    }

    if (out_ref) *out_ref = (ART_NODE*)n16;
    if (out_leaf_slot2) *out_leaf_slot2 = &n16->children[2];
    return n16;
}

static ART_NODE48* t_make_node48_with_one_child(ART_NODE** out_ref,
    UCHAR keyC,
    ART_LEAF** out_leaf)
{
    ART_NODE48* n48 = (ART_NODE48*)art_create_node(NODE48);
    if (!n48) return NULL;
    n48->base.type = NODE48;
    n48->base.num_of_child = 0;
    t_zero(n48->child_index, sizeof(n48->child_index));
    t_zero(n48->children, sizeof(n48->children));

    UCHAR kb[2] = { 'x','y' };
    ART_LEAF* lf = make_leaf(kb, 2, 0x33);
    if (!lf) { free_node((ART_NODE**)&n48); return NULL; }

    n48->children[0] = (ART_NODE*)SET_LEAF(lf);
    n48->child_index[keyC] = 1; // maps 'keyC' to children[0]
    n48->base.num_of_child = 1;

    if (out_ref) *out_ref = (ART_NODE*)n48;
    if (out_leaf) *out_leaf = lf;
    return n48;
}

static ART_NODE256* t_make_node256_with_one_child(ART_NODE** out_ref,
    UCHAR keyC,
    ART_LEAF** out_leaf)
{
    ART_NODE256* n256 = (ART_NODE256*)art_create_node(NODE256);
    if (!n256) return NULL;
    n256->base.type = NODE256;
    n256->base.num_of_child = 0;
    t_zero(n256->children, sizeof(n256->children));

    UCHAR kb[2] = { 'm','n' };
    ART_LEAF* lf = make_leaf(kb, 2, 0x44);
    if (!lf) { free_node((ART_NODE**)&n256); return NULL; }

    n256->children[keyC] = (ART_NODE*)SET_LEAF(lf);
    n256->base.num_of_child = 1;

    if (out_ref) *out_ref = (ART_NODE*)n256;
    if (out_leaf) *out_leaf = lf;
    return n256;
}

static VOID t_free_node_only(ART_NODE** pn)
{
    if (!pn || !*pn) return;
    ART_NODE* n = *pn;

    // best-effort if callers forgot to free leaves (for these focused tests)
    switch (n->type) {
    case NODE4: {
        ART_NODE4* n4 = (ART_NODE4*)n;
        for (USHORT i = 0; i < 4; i++) {
            ART_NODE* ch = n4->children[i];
            if (ch && IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
        }
        break;
    }
    case NODE16: {
        ART_NODE16* n16 = (ART_NODE16*)n;
        for (USHORT i = 0; i < 16; i++) {
            ART_NODE* ch = n16->children[i];
            if (ch && IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
        }
        break;
    }
    case NODE48: {
        ART_NODE48* n48 = (ART_NODE48*)n;
        for (USHORT i = 0; i < 48; i++) {
            ART_NODE* ch = n48->children[i];
            if (ch && IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
        }
        break;
    }
    case NODE256: {
        ART_NODE256* n256 = (ART_NODE256*)n;
        for (USHORT i = 0; i < 256; i++) {
            ART_NODE* ch = n256->children[i];
            if (ch && IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
        }
        break;
    }
    default: break;
    }

    free_node(pn); // sets *pn = NULL
}

// ===============================================================
// Test 1: Guard checks (NULL node/ref)
// ===============================================================
BOOLEAN test_remove_child_guards()
{
    TEST_START("remove_child: guard checks");

    reset_mock_state();
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = remove_child(NULL, NULL, 0, NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: rejects all NULL");

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "1-pre: created NODE4");

    st = remove_child((ART_NODE*)n4, NULL, 0, &n4->children[0]);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: rejects NULL ref");

    t_free_node_only((ART_NODE**)&n4);

    TEST_END("remove_child: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: NODE4 requires leaf
// ===============================================================
BOOLEAN test_remove_child_node4_requires_leaf()
{
    TEST_START("remove_child: NODE4 requires leaf");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE4* n4 = t_make_node4_with_two_leaves(&ref, NULL, NULL, NULL, NULL);
    TEST_ASSERT(n4 != NULL, "2-pre: NODE4(2) made");

    NTSTATUS st = remove_child((ART_NODE*)n4, &ref, /*c*/0, /*leaf*/NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "2.1: missing leaf , invalid parameter");

    t_free_node_only((ART_NODE**)&n4);

    TEST_END("remove_child: NODE4 requires leaf");
    return TRUE;
}

// ===============================================================
// Test 3: NODE16 requires leaf
// ===============================================================
BOOLEAN test_remove_child_node16_requires_leaf()
{
    TEST_START("remove_child: NODE16 requires leaf");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE16* n16 = t_make_node16_with_four_leaves(&ref, NULL);
    TEST_ASSERT(n16 != NULL, "3-pre: NODE16(4) made");

    NTSTATUS st = remove_child((ART_NODE*)n16, &ref, /*c*/0, /*leaf*/NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "3.1: missing leaf , invalid parameter");

    t_free_node_only((ART_NODE**)&n16);

    TEST_END("remove_child: NODE16 requires leaf");
    return TRUE;
}

// ===============================================================
// Test 4: NODE48 success dispatch (existing key)
// ===============================================================
BOOLEAN test_remove_child_node48_success()
{
    TEST_START("remove_child: NODE48 dispatch success");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lf = NULL;
    const UCHAR keyC = 0x7B; // '{'
    ART_NODE48* n48 = t_make_node48_with_one_child(&ref, keyC, &lf);
    TEST_ASSERT(n48 != NULL && lf != NULL, "4-pre: NODE48(1) made");

    NTSTATUS st = remove_child((ART_NODE*)n48, &ref, keyC, /*leaf ignored*/NULL);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: status success");

    // Node had exactly 1 child; after removal the node is dropped.
    TEST_ASSERT(ref == NULL, "4.2: ref is NULL after removing the last child (node freed)");

    // Detached leaf must be freed by the test.
    free_leaf(&lf);

    TEST_END("remove_child: NODE48 dispatch success");
    return TRUE;
}

// ===============================================================
// Test 5: NODE256 success dispatch (existing key)
// ===============================================================
BOOLEAN test_remove_child_node256_success()
{
    TEST_START("remove_child: NODE256 dispatch success");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lf = NULL;
    const UCHAR keyC = 0x22; // '"'
    ART_NODE256* n256 = t_make_node256_with_one_child(&ref, keyC, &lf);
    TEST_ASSERT(n256 != NULL && lf != NULL, "5-pre: NODE256(1) made");

    NTSTATUS st = remove_child((ART_NODE*)n256, &ref, keyC, /*leaf ignored*/ NULL);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: status success");

    // Node had exactly 1 child; after removal the node is dropped.
    TEST_ASSERT(ref == NULL, "5.2: ref is NULL after removing the last child (node freed)");

    // Free the detached leaf.
    free_leaf(&lf);

    TEST_END("remove_child: NODE256 dispatch success");
    return TRUE;
}

// ===============================================================
// Test 6: NODE48 propagate NOT_FOUND for missing key
// ===============================================================
BOOLEAN test_remove_child_node48_not_found()
{
    TEST_START("remove_child: NODE48 NOT_FOUND path");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lf = NULL;
    const UCHAR present = 0x31; // '1'
    const UCHAR absent = 0x32; // '2'
    ART_NODE48* n48 = t_make_node48_with_one_child(&ref, present, &lf);
    TEST_ASSERT(n48 != NULL, "6-pre: NODE48(1) made");

    NTSTATUS st = remove_child((ART_NODE*)n48, &ref, absent, /*leaf ignored*/NULL);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "6.1: missing key returns STATUS_NOT_FOUND");

    t_free_node_only(&ref);

    TEST_END("remove_child: NODE48 NOT_FOUND path");
    return TRUE;
}

// ===============================================================
// Test 7: NODE256 propagate NOT_FOUND for missing key
// ===============================================================
BOOLEAN test_remove_child_node256_not_found()
{
    TEST_START("remove_child: NODE256 NOT_FOUND path");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lf = NULL;
    const UCHAR present = 0xA0;
    const UCHAR absent = 0xA1;
    ART_NODE256* n256 = t_make_node256_with_one_child(&ref, present, &lf);
    TEST_ASSERT(n256 != NULL, "7-pre: NODE256(1) made");

    NTSTATUS st = remove_child((ART_NODE*)n256, &ref, absent, /*leaf ignored*/NULL);
    TEST_ASSERT(st == STATUS_NOT_FOUND, "7.1: missing key returns STATUS_NOT_FOUND");

    t_free_node_only(&ref);

    TEST_END("remove_child: NODE256 NOT_FOUND path");
    return TRUE;
}

// ===============================================================
// Test 8: NODE4 success dispatch
//   (remove first child using its slot pointer)
// ===============================================================
BOOLEAN test_remove_child_node4_success()
{
    TEST_START("remove_child: NODE4 dispatch success (2 -> collapse)");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE** slot0 = NULL;
    ART_NODE** slot1 = NULL;
    ART_LEAF* l0 = NULL;
    ART_LEAF* l1 = NULL;

    ART_NODE4* n4 = t_make_node4_with_two_leaves(&ref, &slot0, &slot1, &l0, &l1);
    TEST_ASSERT(n4 != NULL && slot0 && slot1 && l0 && l1, "8-pre: NODE4(2) made");

    TEST_ASSERT(n4->base.num_of_child == 2, "8-pre2: child count is 2 before removal");

    // Remove the first leaf (slot0). For NODE4 with 2 children this must collapse.
    NTSTATUS st = remove_child((ART_NODE*)n4, &ref, /*c ignored*/0, /*leaf*/slot0);
    TEST_ASSERT(NT_SUCCESS(st), "8.1: remove_child status success");

    // After collapse, ref must be the remaining child (a leaf), and the NODE4 is freed.
    TEST_ASSERT(ref != NULL, "8.2: ref valid after removal");
    TEST_ASSERT(IS_LEAF(ref), "8.3: NODE4 collapsed to remaining leaf");
    TEST_ASSERT(LEAF_RAW(ref) == l1, "8.4: remaining leaf is l1");

    // The removed leaf is detached; free it explicitly.
    free_leaf(&l0);
    TEST_ASSERT(l0 == NULL, "8.5: removed leaf freed");

    // Free the remaining leaf (now held in ref)
    {
        ART_LEAF* remain = LEAF_RAW(ref);
        free_leaf(&remain);
        TEST_ASSERT(remain == NULL, "8.6: remaining leaf freed");
    }

    // ref was an encoded leaf pointer; nothing else to free.
    ref = NULL;

    TEST_END("remove_child: NODE4 dispatch success (2 -> collapse)");
    return TRUE;
}


// ===============================================================
// Test 9: NODE16 success dispatch
//   (remove position 2 using &node->children[2])
// ===============================================================
BOOLEAN test_remove_child_node16_success()
{
    TEST_START("remove_child: NODE16 dispatch success");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE** slot2 = NULL;

    ART_NODE16* n16 = t_make_node16_with_four_leaves(&ref, &slot2);
    TEST_ASSERT(n16 != NULL && slot2 != NULL, "9-pre: NODE16(4) made");

    // Capture the leaf to be removed BEFORE calling remove_child
    TEST_ASSERT(*slot2 != NULL && IS_LEAF(*slot2), "9-pre2: slot2 holds a leaf");
    ART_LEAF* removed = LEAF_RAW(*slot2);

    NTSTATUS st = remove_child((ART_NODE*)n16, &ref, /*c ignored*/0, /*leaf*/slot2);
    TEST_ASSERT(NT_SUCCESS(st), "9.1: status success");
    TEST_ASSERT(ref != NULL, "9.2: ref valid after removal");

    // Detached leaf must be freed explicitly
    free_leaf(&removed);
    TEST_ASSERT(removed == NULL, "9.3: removed leaf freed");

    // Clean up remaining structure (may be NODE16 -> NODE4 migration)
    if (ref && IS_LEAF(ref)) {
        ART_LEAF* remain = LEAF_RAW(ref);
        free_leaf(&remain);
        TEST_ASSERT(remain == NULL, "9.4: remaining leaf freed");
        ref = NULL;
    }
    else {
        t_free_node_only(&ref);
        TEST_ASSERT(ref == NULL, "9.5: node freed");
    }

    TEST_END("remove_child: NODE16 dispatch success");
    return TRUE;
}


// ===============================================================
// Test 10: Invalid node type
// ===============================================================
BOOLEAN test_remove_child_invalid_type()
{
    TEST_START("remove_child: invalid node type");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_NODE* bogus = (ART_NODE*)art_create_node(NODE4);
    TEST_ASSERT(bogus != NULL, "10-pre: created node");
    bogus->type = (NODE_TYPE)0; // invalid

    ref = bogus;
    NTSTATUS st = remove_child(bogus, &ref, 0, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "10.1: invalid type rejected");

    t_free_node_only(&bogus);

    TEST_END("remove_child: invalid node type");
    return TRUE;
}

// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_remove_child_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting remove_child() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_remove_child_guards())                 all = FALSE; // 1
    if (!test_remove_child_node4_requires_leaf())    all = FALSE; // 2
    if (!test_remove_child_node16_requires_leaf())   all = FALSE; // 3
    if (!test_remove_child_node48_success())         all = FALSE; // 4
    if (!test_remove_child_node256_success())        all = FALSE; // 5
    if (!test_remove_child_node48_not_found())       all = FALSE; // 6
    if (!test_remove_child_node256_not_found())      all = FALSE; // 7
    if (!test_remove_child_node4_success())          all = FALSE; // 8
    if (!test_remove_child_node16_success())         all = FALSE; // 9
    if (!test_remove_child_invalid_type())           all = FALSE; // 10

    DbgPrint("\n========================================\n");
    if (all) {
        DbgPrint("ALL remove_child() TESTS PASSED! \n");
    }
    else {
        DbgPrint("SOME remove_child() TESTS FAILED! \n");
    }
    DbgPrint("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
