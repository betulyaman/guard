#include "test_art.h"

STATIC NTSTATUS recursive_delete_all_internal(_Inout_ ART_TREE* tree, _In_opt_ ART_NODE* node, _Inout_ PULONG leaf_count, _Inout_ PULONG node_count, _In_ USHORT recursion_depth);

// ---------- small local helpers (no CRT) ----------
static VOID da_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* da_make_node4(void) {
    return (ART_NODE4*)art_create_node(NODE4);
}
static ART_NODE16* da_make_node16(void) {
    return (ART_NODE16*)art_create_node(NODE16);
}
static ART_NODE48* da_make_node48(void) {
    return (ART_NODE48*)art_create_node(NODE48);
}
static ART_NODE256* da_make_node256(void) {
    return (ART_NODE256*)art_create_node(NODE256);
}

// Build a NODE4 with up to 4 children (each child pointer already leaf or node)
static BOOLEAN da_node4_set(ART_NODE4* n4,
    const UCHAR* keys, USHORT count,
    ART_NODE* const* children)
{
    if (!n4 || !keys || !children || count > 4) return FALSE;
    da_zero(n4->keys, sizeof(n4->keys));
    da_zero(n4->children, sizeof(n4->children));
    for (USHORT i = 0; i < count; i++) {
        n4->keys[i] = keys[i];
        n4->children[i] = children[i];
    }
    n4->base.num_of_child = count;
    return TRUE;
}

// Build a NODE16 similarly
static BOOLEAN da_node16_set(ART_NODE16* n16,
    const UCHAR* keys, USHORT count,
    ART_NODE* const* children)
{
    if (!n16 || !keys || !children || count > 16) return FALSE;
    da_zero(n16->keys, sizeof(n16->keys));
    da_zero(n16->children, sizeof(n16->children));
    for (USHORT i = 0; i < count; i++) {
        n16->keys[i] = keys[i];
        n16->children[i] = children[i];
    }
    n16->base.num_of_child = count;
    return TRUE;
}

// Build a NODE48 with sparse mapping
static BOOLEAN da_node48_map(ART_NODE48* n48,
    const UCHAR* key_bytes, USHORT count,
    ART_NODE* const* children)
{
    if (!n48 || !key_bytes || !children || count > 48) return FALSE;
    da_zero(n48->child_index, sizeof(n48->child_index));
    da_zero(n48->children, sizeof(n48->children));
    for (USHORT i = 0; i < count; i++) {
        n48->children[i] = children[i];
        n48->child_index[key_bytes[i]] = (UCHAR)(i + 1); // +1 encoded
    }
    n48->base.num_of_child = count;
    return TRUE;
}

// Build a NODE256 with direct indices
static BOOLEAN da_node256_set(ART_NODE256* n256,
    const UCHAR* idx, USHORT count,
    ART_NODE* const* children)
{
    if (!n256 || !idx || !children || count > 256) return FALSE;
    da_zero(n256->children, sizeof(n256->children));
    for (USHORT i = 0; i < count; i++) {
        n256->children[idx[i]] = children[i];
    }
    n256->base.num_of_child = count;
    return TRUE;
}

// Recursively free a tree (leaves+internal) built by these tests
static VOID da_free_all(ART_NODE** pref)
{
    if (!pref || !*pref) return;
    ART_NODE* n = *pref;
    if (IS_LEAF(n)) {
        ART_LEAF* lf = LEAF_RAW(n);
        free_leaf(&lf);
        *pref = NULL;
        return;
    }
    switch (n->type) {
    case NODE4: {
        ART_NODE4* p = (ART_NODE4*)n;
        for (USHORT i = 0; i < 4; i++) { ART_NODE* ch = p->children[i]; if (ch) { da_free_all(&ch); } }
        break;
    }
    case NODE16: {
        ART_NODE16* p = (ART_NODE16*)n;
        for (USHORT i = 0; i < 16; i++) { ART_NODE* ch = p->children[i]; if (ch) { da_free_all(&ch); } }
        break;
    }
    case NODE48: {
        ART_NODE48* p = (ART_NODE48*)n;
        for (USHORT i = 0; i < 48; i++) { ART_NODE* ch = p->children[i]; if (ch) { da_free_all(&ch); } }
        break;
    }
    case NODE256: {
        ART_NODE256* p = (ART_NODE256*)n;
        for (USHORT i = 0; i < 256; i++) { ART_NODE* ch = p->children[i]; if (ch) { da_free_all(&ch); } }
        break;
    }
    default: break;
    }
    free_node(pref);
}

// ============================
// Test 1: Guards & overflow
// ============================
BOOLEAN test_delete_all_internal_guards()
{
    TEST_START("recursive_delete_all_internal: guards & overflow");

    ULONG leaves = 1234; // sentinel
    ULONG nodes = 4321; // sentinel
    NTSTATUS st;

    // 1.1 NULL argümanlar -> STATUS_SUCCESS (no-op), sayaçlar değişmez
    leaves = 7; nodes = 11;
#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_delete_all_internal(NULL, NULL, &leaves, &nodes, 0);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.1a: NULL tree+node ok");
    TEST_ASSERT(leaves == 7 && nodes == 11, "1.1b: counters unchanged");

    leaves = 8; nodes = 12;
#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_delete_all_internal((ART_TREE*)1, NULL, &leaves, &nodes, 0);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.1c: NULL node ok");
    TEST_ASSERT(leaves == 8 && nodes == 12, "1.1d: counters unchanged");

    // leaf_count == NULL → no-op
#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_delete_all_internal((ART_TREE*)1, (ART_NODE*)1, NULL, &nodes, 0);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.1e: NULL leaf_count -> STATUS_SUCCESS");

    // node_count == NULL → no-op
#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_delete_all_internal((ART_TREE*)1, (ART_NODE*)1, &leaves, NULL, 0);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.1f: NULL node_count -> STATUS_SUCCESS");

    // 1.2 Recursion depth overflow
#pragma warning(push)
#pragma warning(disable:6387)
    st = recursive_delete_all_internal((ART_TREE*)1, (ART_NODE*)1, &leaves, &nodes,
        (USHORT)(MAX_RECURSION_DEPTH + 1));
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_STACK_OVERFLOW, "1.2: overflow returns STATUS_STACK_OVERFLOW");

    TEST_END("recursive_delete_all_internal: guards & overflow");
    return TRUE;
}

// ============================
// Test 2: Single leaf
// ============================
BOOLEAN test_delete_all_internal_single_leaf()
{
    TEST_START("recursive_delete_all_internal: single leaf");

    // Build a single leaf node (using tagged leaf pointer)
    UCHAR key = 'a';
    ART_LEAF* lf = make_leaf(&key, 1, 0x11);
    TEST_ASSERT(lf != NULL, "2-pre: leaf allocated");

    ART_NODE* n = (ART_NODE*)SET_LEAF(lf);
    ART_TREE t; da_zero(&t, sizeof(t));

    ULONG del = 0;
    ULONG node_cnt = 0; // track total freed nodes (leaves count as nodes too)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, n, &del, &node_cnt, 0);

    TEST_ASSERT(NT_SUCCESS(st), "2.1: returns success");
    TEST_ASSERT(del == 1, "2.2: deletes exactly 1 (the leaf)");
    // (Optional) You could also check node_cnt == 1, but not required by this test.

    TEST_END("recursive_delete_all_internal: single leaf");
    return TRUE;
}

// ============================
// Test 3: NODE4 with 2 leaves
// ============================
BOOLEAN test_delete_all_internal_node4_simple()
{
    TEST_START("recursive_delete_all_internal: NODE4 simple");

    ART_NODE4* n4 = da_make_node4();
    TEST_ASSERT(n4 != NULL, "3-pre: NODE4 created");

    // children: two leaves under keys {1, 3}
    UCHAR kb[2] = { 1, 3 };
    ART_LEAF* l0 = make_leaf(&kb[0], 1, 0xA);
    ART_LEAF* l1 = make_leaf(&kb[1], 1, 0xB);
    TEST_ASSERT(l0 && l1, "3-pre: leaves created");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(da_node4_set(n4, kb, 2, ch), "3-pre: NODE4 wired");

    ART_TREE t; da_zero(&t, sizeof(t));
    ULONG del = 0;         // leaf_count
    ULONG node_cnt = 0;    // total freed nodes (leaves count as nodes as well)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, (ART_NODE*)n4, &del, &node_cnt, 0);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: success");

    // Expect 2 leaves and 3 total nodes (2 leaves + the NODE4)
    TEST_ASSERT(del == 2, "3.2: deletes exactly 2 leaves");
    TEST_ASSERT(node_cnt == 3, "3.3: frees 3 total nodes (2 leaves + NODE4)");

    TEST_END("recursive_delete_all_internal: NODE4 simple");
    return TRUE;
}

// ============================
// Test 4: NODE16 with 3 leaves
// ============================
BOOLEAN test_delete_all_internal_node16_three()
{
    TEST_START("recursive_delete_all_internal: NODE16 three leaves");

    ART_NODE16* n16 = da_make_node16();
    TEST_ASSERT(n16 != NULL, "4-pre: NODE16 created");

    UCHAR kb[3] = { 2, 4, 6 };
    ART_LEAF* l0 = make_leaf(&kb[0], 1, 0x10);
    ART_LEAF* l1 = make_leaf(&kb[1], 1, 0x20);
    ART_LEAF* l2 = make_leaf(&kb[2], 1, 0x30);
    TEST_ASSERT(l0 && l1 && l2, "4-pre: leaves created");

    ART_NODE* ch[3] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1), (ART_NODE*)SET_LEAF(l2) };
    TEST_ASSERT(da_node16_set(n16, kb, 3, ch), "4-pre: NODE16 wired");

    ART_TREE t; da_zero(&t, sizeof(t));
    ULONG del = 0;       // leaf_count
    ULONG node_cnt = 0;  // total freed nodes (includes leaves)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, (ART_NODE*)n16, &del, &node_cnt, 0);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: success");

    TEST_ASSERT(del == 3, "4.2: deletes exactly 3 leaves");
    TEST_ASSERT(node_cnt == 4, "4.3: frees 4 total nodes (3 leaves + NODE16)");

    TEST_END("recursive_delete_all_internal: NODE16 three leaves");
    return TRUE;
}


// ============================
// Test 5: NODE48 sparse map (2 leaves)
// ============================
BOOLEAN test_delete_all_internal_node48_sparse()
{
    TEST_START("recursive_delete_all_internal: NODE48 sparse");

    ART_NODE48* n48 = da_make_node48();
    TEST_ASSERT(n48 != NULL, "5-pre: NODE48 created");

    UCHAR map_keys[2] = { 7, 200 };
    ART_LEAF* l0 = make_leaf(&map_keys[0], 1, 0xAA);
    ART_LEAF* l1 = make_leaf(&map_keys[1], 1, 0xBB);
    TEST_ASSERT(l0 && l1, "5-pre: leaves created");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(da_node48_map(n48, map_keys, 2, ch), "5-pre: NODE48 mapped");

    ART_TREE t; da_zero(&t, sizeof(t));
    ULONG del = 0;       // leaf_count
    ULONG node_cnt = 0;  // total freed nodes (includes leaves)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, (ART_NODE*)n48, &del, &node_cnt, 0);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: success");
    TEST_ASSERT(del == 2, "5.2: deletes exactly 2 leaves");
    TEST_ASSERT(node_cnt == 3, "5.3: frees 3 total nodes (2 leaves + NODE48)");

    TEST_END("recursive_delete_all_internal: NODE48 sparse");
    return TRUE;
}

// ============================
// Test 6: NODE256 (2 direct + 1 internal child)
// ============================
BOOLEAN test_delete_all_internal_node256_mixed()
{
    TEST_START("recursive_delete_all_internal: NODE256 mixed");

    ART_NODE256* n256 = da_make_node256();
    TEST_ASSERT(n256 != NULL, "6-pre: NODE256 created");

    // direct leaves at indices 0 and 255
    UCHAR ixs[3] = { 0, 255, 100 }; // third slot will host an internal NODE4
    ART_LEAF* l0 = make_leaf(&ixs[0], 1, 0x01);
    ART_LEAF* l1 = make_leaf(&ixs[1], 1, 0x02);

    // internal child under 100 -> NODE4 with one leaf
    ART_NODE4* inner = da_make_node4();
    TEST_ASSERT(inner && l0 && l1, "6-pre: allocated children");

    UCHAR ksub = 5;
    ART_LEAF* lsub = make_leaf(&ksub, 1, 0x33);
    TEST_ASSERT(lsub != NULL, "6-pre: inner leaf ok");
    ART_NODE* ich = (ART_NODE*)SET_LEAF(lsub);
    UCHAR ikey = ksub;
    TEST_ASSERT(da_node4_set(inner, &ikey, 1, &ich), "6-pre: inner wired");

    ART_NODE* top_children[3] = {
        (ART_NODE*)SET_LEAF(l0),
        (ART_NODE*)SET_LEAF(l1),
        (ART_NODE*)inner
    };
    TEST_ASSERT(da_node256_set(n256, ixs, 3, top_children), "6-pre: NODE256 set");

    ART_TREE t; da_zero(&t, sizeof(t));
    ULONG del = 0;        // leaf_count
    ULONG node_cnt = 0;   // total freed nodes (includes leaves)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, (ART_NODE*)n256, &del, &node_cnt, 0);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: success");

    // Expected deletions: 3 leaves; total nodes freed = 5 (3 leaves + inner NODE4 + top NODE256)
    TEST_ASSERT(del == 3, "6.2: deletes exactly 3 leaves");
    TEST_ASSERT(node_cnt == 5, "6.3: frees 5 total nodes (3 leaves + NODE4 + NODE256)");

    TEST_END("recursive_delete_all_internal: NODE256 mixed");
    return TRUE;
}

// ============================
// Test 7: Deep structure (NODE4->NODE16->leaves)
// ============================
BOOLEAN test_delete_all_internal_deep()
{
    TEST_START("recursive_delete_all_internal: deep structure");

    ART_NODE4* n4 = da_make_node4();
    ART_NODE16* n16 = da_make_node16();
    TEST_ASSERT(n4 && n16, "7-pre: internal nodes created");

    // n16 with two leaves
    UCHAR k16[2] = { 10, 20 };
    ART_LEAF* l0 = make_leaf(&k16[0], 1, 0x111);
    ART_LEAF* l1 = make_leaf(&k16[1], 1, 0x222);
    TEST_ASSERT(l0 && l1, "7-pre: leaves created");

    ART_NODE* n16ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(da_node16_set(n16, k16, 2, n16ch), "7-pre: NODE16 wired");

    // n4 has one child key 0x33 -> n16
    UCHAR k4 = 0x33;
    ART_NODE* child = (ART_NODE*)n16;
    TEST_ASSERT(da_node4_set(n4, &k4, 1, &child), "7-pre: NODE4 wired");

    ART_TREE t; da_zero(&t, sizeof(t));
    ULONG del = 0;        // leaf_count
    ULONG node_cnt = 0;   // total freed nodes (includes leaves)

    // FIX: pass both leaf_count and node_count, plus initial recursion depth = 0
    NTSTATUS st = recursive_delete_all_internal(&t, (ART_NODE*)n4, &del, &node_cnt, 0);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: success");

    // Expected: 2 leaves; total nodes freed = 4 (2 leaves + NODE16 + NODE4)
    TEST_ASSERT(del == 2, "7.2: deletes exactly 2 leaves");
    TEST_ASSERT(node_cnt == 4, "7.3: frees 4 total nodes (2 leaves + NODE16 + NODE4)");

    TEST_END("recursive_delete_all_internal: deep structure");
    return TRUE;
}

// ============================
// Suite runner
// ============================
NTSTATUS run_all_recursive_delete_all_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting recursive_delete_all_internal() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_delete_all_internal_guards())         all = FALSE; // (1)
    if (!test_delete_all_internal_single_leaf())    all = FALSE; // (2)
    if (!test_delete_all_internal_node4_simple())   all = FALSE; // (3)
    if (!test_delete_all_internal_node16_three())   all = FALSE; // (4)
    if (!test_delete_all_internal_node48_sparse())  all = FALSE; // (5)
    if (!test_delete_all_internal_node256_mixed())  all = FALSE; // (6)
    if (!test_delete_all_internal_deep())           all = FALSE; // (7)

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL recursive_delete_all_internal() TESTS PASSED! \n");
    }
    else {
        LOG_MSG("SOME recursive_delete_all_internal() TESTS FAILED! \n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
