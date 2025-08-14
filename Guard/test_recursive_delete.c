#if UNIT_TEST  

#include "test_art.h"

// Under test
STATIC ART_LEAF* recursive_delete(_In_opt_ ART_NODE* node,
    _Inout_ ART_NODE** ref,
    _In_reads_bytes_(key_length) CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ USHORT depth);

// ====== tiny helpers ======
static VOID rd_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }
static ART_NODE4* rd_make_node4_with_two_leaves(ART_NODE** out_ref,
    UCHAR kA, UCHAR kB,
    ART_LEAF** out_lA,
    ART_LEAF** out_lB)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    rd_zero(n4->keys, sizeof(n4->keys));
    rd_zero(n4->children, sizeof(n4->children));

    UCHAR keyA[1] = { kA };
    UCHAR keyB[1] = { kB };

    ART_LEAF* lA = make_leaf(keyA, 1, 0xA1);
    ART_LEAF* lB = make_leaf(keyB, 1, 0xB2);
    if (!lA || !lB) {
        if (lA) free_leaf(&lA);
        if (lB) free_leaf(&lB);
        free_node((ART_NODE**)&n4);
        return NULL;
    }

    n4->keys[0] = kA; n4->children[0] = (ART_NODE*)SET_LEAF(lA);
    n4->keys[1] = kB; n4->children[1] = (ART_NODE*)SET_LEAF(lB);
    n4->base.num_of_child = 2;

    if (out_ref) *out_ref = (ART_NODE*)n4;
    if (out_lA) *out_lA = lA;
    if (out_lB) *out_lB = lB;
    return n4;
}

static ART_NODE4* rd_make_node4_with_prefix_and_leaf(ART_NODE** out_ref,
    UCHAR prefixByte,
    UCHAR childKey,
    ART_LEAF** out_leaf)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    n4->base.prefix_length = 1;
    rd_zero(n4->base.prefix, sizeof(n4->base.prefix));
    n4->base.prefix[0] = prefixByte;

    rd_zero(n4->keys, sizeof(n4->keys));
    rd_zero(n4->children, sizeof(n4->children));

    UCHAR key2[2] = { prefixByte, childKey };
    ART_LEAF* lf = make_leaf(key2, 2, 0xCC);
    if (!lf) { free_node((ART_NODE**)&n4); return NULL; }

    n4->keys[0] = childKey;
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 1;

    if (out_ref) *out_ref = (ART_NODE*)n4;
    if (out_leaf) *out_leaf = lf;
    return n4;
}

static ART_NODE4* rd_make_two_level_internal_then_leaf(ART_NODE** out_ref,
    UCHAR pfx, UCHAR midKey, UCHAR lastKey,
    ART_LEAF** out_leaf)
{
    ART_NODE4* root = (ART_NODE4*)art_create_node(NODE4);
    if (!root) return NULL;
    root->base.type = NODE4;
    root->base.prefix_length = 1;
    root->base.num_of_child = 0;
    rd_zero(root->base.prefix, sizeof(root->base.prefix));
    root->base.prefix[0] = pfx;
    rd_zero(root->keys, sizeof(root->keys));
    rd_zero(root->children, sizeof(root->children));

    ART_NODE4* mid = (ART_NODE4*)art_create_node(NODE4);
    if (!mid) { free_node((ART_NODE**)&root); return NULL; }
    mid->base.type = NODE4;
    mid->base.num_of_child = 0;
    mid->base.prefix_length = 0;
    rd_zero(mid->keys, sizeof(mid->keys));
    rd_zero(mid->children, sizeof(mid->children));

    UCHAR fullKey[3] = { pfx, midKey, lastKey };
    ART_LEAF* lf = make_leaf(fullKey, 3, 0xDD);
    if (!lf) {
        free_node((ART_NODE**)&mid);
        free_node((ART_NODE**)&root);
        return NULL;
    }

    mid->keys[0] = lastKey;
    mid->children[0] = (ART_NODE*)SET_LEAF(lf);
    mid->base.num_of_child = 1;

    root->keys[0] = midKey;
    root->children[0] = (ART_NODE*)mid;
    root->base.num_of_child = 1;

    if (out_ref) *out_ref = (ART_NODE*)root;
    if (out_leaf) *out_leaf = lf;
    return root;
}

static VOID rd_free_tree(ART_NODE** pref)
{
    if (!pref || !*pref) return;
    ART_NODE* n = *pref;

    switch (n->type) {
    case NODE4: {
        ART_NODE4* n4 = (ART_NODE4*)n;
        for (USHORT i = 0; i < 4; i++) {
            ART_NODE* ch = n4->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ART_NODE* sub = ch;
                rd_free_tree(&sub);
            }
        }
        break;
    }
    case NODE16: {
        ART_NODE16* n16 = (ART_NODE16*)n;
        for (USHORT i = 0; i < 16; i++) {
            ART_NODE* ch = n16->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ART_NODE* sub = ch;
                rd_free_tree(&sub);
            }
        }
        break;
    }
    case NODE48: {
        ART_NODE48* n48 = (ART_NODE48*)n;
        for (USHORT i = 0; i < 48; i++) {
            ART_NODE* ch = n48->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ART_NODE* sub = ch;
                rd_free_tree(&sub);
            }
        }
        break;
    }
    case NODE256: {
        ART_NODE256* n256 = (ART_NODE256*)n;
        for (USHORT i = 0; i < 256; i++) {
            ART_NODE* ch = n256->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ART_NODE* sub = ch;
                rd_free_tree(&sub);
            }
        }
        break;
    }
    default: break;
    }

    free_node(pref);
}

// ===============================================================
// Test 1: Guard checks (NULLs and key_length==0)
// ===============================================================
BOOLEAN test_recursive_delete_guards()
{
    TEST_START("recursive_delete: guard checks");

    reset_mock_state();

    UCHAR k[1] = { 'a' };
    ART_NODE* ref = NULL;

#pragma warning(push)
#pragma warning(disable: 6387)
    ART_LEAF* out = recursive_delete(NULL, NULL, NULL, 0, 0);
#pragma warning(pop)
    TEST_ASSERT(out == NULL, "1.1: all NULL returns NULL");

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "1-pre: node allocated");
    ref = (ART_NODE*)n4;

    out = recursive_delete(NULL, &ref, k, 1, 0);
    TEST_ASSERT(out == NULL, "1.2: NULL node");

    out = recursive_delete((ART_NODE*)n4, NULL, k, 1, 0);
    TEST_ASSERT(out == NULL, "1.3: NULL ref");

#pragma warning(push)
#pragma warning(disable: 6387)
    out = recursive_delete((ART_NODE*)n4, &ref, NULL, 1, 0);
    TEST_ASSERT(out == NULL, "1.4: NULL key");
#pragma warning(pop)

    out = recursive_delete((ART_NODE*)n4, &ref, k, 0, 0);
    TEST_ASSERT(out == NULL, "1.5: key_length == 0");

    rd_free_tree(&ref);

    TEST_END("recursive_delete: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: Leaf match at depth 0 -> remove and return leaf
// ===============================================================
BOOLEAN test_recursive_delete_leaf_match()
{
    TEST_START("recursive_delete: leaf match");

    reset_mock_state();

    UCHAR keyA[1] = { 'a' };
    ART_LEAF* lf = make_leaf(keyA, 1, 0x11);
    TEST_ASSERT(lf != NULL, "2-pre: leaf created");

    ART_NODE* enc = (ART_NODE*)SET_LEAF(lf);
    ART_NODE* ref = enc;

    ART_LEAF* out = recursive_delete(enc, &ref, keyA, 1, 0);
    TEST_ASSERT(out == lf, "2.1: returns removed leaf");
    TEST_ASSERT(ref == NULL, "2.2: ref cleared");

    if (out) free_leaf(&out);

    TEST_END("recursive_delete: leaf match");
    return TRUE;
}

// ===============================================================
// Test 3: Leaf no match -> NULL, no change
// ===============================================================
BOOLEAN test_recursive_delete_leaf_no_match()
{
    TEST_START("recursive_delete: leaf no match");

    reset_mock_state();

    UCHAR keyA[1] = { 'a' };
    UCHAR keyB[1] = { 'b' };
    ART_LEAF* lf = make_leaf(keyA, 1, 0x22);
    TEST_ASSERT(lf != NULL, "3-pre: leaf created");

    ART_NODE* enc = (ART_NODE*)SET_LEAF(lf);
    ART_NODE* ref = enc;

    ART_LEAF* out = recursive_delete(enc, &ref, keyB, 1, 0);
    TEST_ASSERT(out == NULL, "3.1: returns NULL");
    TEST_ASSERT(ref == enc, "3.2: ref unchanged");

    free_leaf(&lf);

    TEST_END("recursive_delete: leaf no match");
    return TRUE;
}

// ===============================================================
// Test 4: Internal with prefix – mismatch -> NULL
// ===============================================================
BOOLEAN test_recursive_delete_prefix_mismatch()
{
    TEST_START("recursive_delete: prefix mismatch");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* n4 = rd_make_node4_with_prefix_and_leaf(&ref, 'x', 'a', &leaf);
    TEST_ASSERT(n4 != NULL, "4-pre: NODE4 with prefix");

    UCHAR wrong[2] = { 'y','a' };
    ART_LEAF* out = recursive_delete((ART_NODE*)n4, &ref, wrong, 2, 0);
    TEST_ASSERT(out == NULL, "4.1: returns NULL");

    rd_free_tree(&ref);

    TEST_END("recursive_delete: prefix mismatch");
    return TRUE;
}

// ===============================================================
// Test 5: Internal with prefix – match -> delete leaf child
// ===============================================================
BOOLEAN test_recursive_delete_prefix_match_delete()
{
    TEST_START("recursive_delete: prefix match -> delete");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* n4 = rd_make_node4_with_prefix_and_leaf(&ref, 'x', 'a', &leaf);
    TEST_ASSERT(n4 != NULL, "5-pre: NODE4 with prefix");

    UCHAR full[2] = { 'x','a' };
    ART_LEAF* out = recursive_delete((ART_NODE*)n4, &ref, full, 2, 0);
    TEST_ASSERT(out == leaf, "5.1: removed leaf returned");
    if (out) free_leaf(&out);

    rd_free_tree(&ref);

    TEST_END("recursive_delete: prefix match -> delete");
    return TRUE;
}

// ===============================================================
// Test 6: Missing child -> NULL
// ===============================================================
BOOLEAN test_recursive_delete_missing_child()
{
    TEST_START("recursive_delete: missing child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lA = NULL, * lB = NULL;
    ART_NODE4* n4 = rd_make_node4_with_two_leaves(&ref, 'a', 'b', &lA, &lB);
    TEST_ASSERT(n4 != NULL, "6-pre: NODE4(2) ready");

    UCHAR k[1] = { 'c' };
    ART_LEAF* out = recursive_delete((ART_NODE*)n4, &ref, k, 1, 0);
    TEST_ASSERT(out == NULL, "6.1: returns NULL if child absent");

    rd_free_tree(&ref);

    TEST_END("recursive_delete: missing child");
    return TRUE;
}

// ===============================================================
// Test 7: Depth > 0 – delete deeper leaf (two-level) using parent slot
// ===============================================================
BOOLEAN test_recursive_delete_two_level_depth()
{
    TEST_START("recursive_delete: two-level with depth");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* root = rd_make_two_level_internal_then_leaf(&ref, 'p', 'q', 'r', &leaf);
    TEST_ASSERT(root != NULL, "7-pre: two-level tree created");

    UCHAR full_key[3] = { 'p','q','r' };
    ART_NODE** child_slot = &(((ART_NODE4*)ref)->children[0]);
    ART_NODE* child_node = *child_slot;
    TEST_ASSERT(!IS_LEAF(child_node), "7-pre2: mid node is internal");

    ART_LEAF* out = recursive_delete(child_node, child_slot, full_key, 3, 2);
    TEST_ASSERT(out == leaf, "7.1: removed deeper leaf");
    if (out) free_leaf(&out);

    if (ref) {
        if (IS_LEAF(ref)) {
            ART_LEAF* remain = LEAF_RAW(ref);
            free_leaf(&remain);
            ref = NULL;
        }
        else {
            rd_free_tree(&ref);
        }
    }

    TEST_END("recursive_delete: two-level with depth");
    return TRUE;
}

// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_recursive_delete_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting recursive_delete() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_recursive_delete_guards())               all = FALSE;
    if (!test_recursive_delete_leaf_match())           all = FALSE;
    if (!test_recursive_delete_leaf_no_match())        all = FALSE;
    if (!test_recursive_delete_prefix_mismatch())      all = FALSE;
    if (!test_recursive_delete_prefix_match_delete())  all = FALSE;
    if (!test_recursive_delete_missing_child())        all = FALSE;
    if (!test_recursive_delete_two_level_depth())      all = FALSE;

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL recursive_delete() TESTS PASSED! \n");
    }
    else {
        LOG_MSG("SOME recursive_delete() TESTS FAILED! \n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif
