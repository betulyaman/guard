#if UNIT_TEST

#include "test_art.h"

// Under test
STATIC NTSTATUS force_delete_all_iterative(_Inout_ ULONG* leaf_count,
    _Inout_ ULONG* node_count,
    _Inout_ ART_NODE** proot);

// ---------- local builders / helpers (no CRT) ----------
STATIC VOID fd_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

STATIC ART_NODE4* fd_make_node4(void) {
    ART_NODE4* n = (ART_NODE4*)art_create_node(NODE4);
    if (!n) return NULL;
    n->base.type = NODE4;
    n->base.num_of_child = 0;
    fd_zero(n->keys, sizeof(n->keys));
    fd_zero(n->children, sizeof(n->children));
    return n;
}

STATIC ART_NODE16* fd_make_node16(void) {
    ART_NODE16* n = (ART_NODE16*)art_create_node(NODE16);
    if (!n) return NULL;
    n->base.type = NODE16;
    n->base.num_of_child = 0;
    fd_zero(n->keys, sizeof(n->keys));
    fd_zero(n->children, sizeof(n->children));
    return n;
}

STATIC ART_NODE48* fd_make_node48(void) {
    ART_NODE48* n = (ART_NODE48*)art_create_node(NODE48);
    if (!n) return NULL;
    n->base.type = NODE48;
    n->base.num_of_child = 0;
    fd_zero(n->child_index, sizeof(n->child_index));
    fd_zero(n->children, sizeof(n->children));
    return n;
}

STATIC ART_NODE256* fd_make_node256(void) {
    ART_NODE256* n = (ART_NODE256*)art_create_node(NODE256);
    if (!n) return NULL;
    n->base.type = NODE256;
    n->base.num_of_child = 0;
    fd_zero(n->children, sizeof(n->children));
    return n;
}

STATIC BOOLEAN fd_node4_set(ART_NODE4* n4,
    const UCHAR* keys, USHORT count,
    ART_NODE* const* children)
{
    if (!n4 || !keys || !children || count > 4) return FALSE;
    for (USHORT i = 0; i < count; i++) {
        n4->keys[i] = keys[i];
        n4->children[i] = children[i];
    }
    n4->base.num_of_child = count;
    return TRUE;
}

STATIC BOOLEAN fd_node16_set(ART_NODE16* n16,
    const UCHAR* keys, USHORT count,
    ART_NODE* const* children)
{
    if (!n16 || !keys || !children || count > 16) return FALSE;
    for (USHORT i = 0; i < count; i++) {
        n16->keys[i] = keys[i];
        n16->children[i] = children[i];
    }
    n16->base.num_of_child = count;
    return TRUE;
}

STATIC BOOLEAN fd_node48_map(ART_NODE48* n48,
    const UCHAR* key_bytes, USHORT count,
    ART_NODE* const* children)
{
    if (!n48 || !key_bytes || !children || count > 48) return FALSE;
    for (USHORT i = 0; i < count; i++) {
        n48->children[i] = children[i];
        n48->child_index[key_bytes[i]] = (UCHAR)(i + 1); // 1..48
    }
    n48->base.num_of_child = count;
    return TRUE;
}

STATIC BOOLEAN fd_node256_set(ART_NODE256* n256,
    const UCHAR* idx, USHORT count,
    ART_NODE* const* children)
{
    if (!n256 || !idx || !children || count > 256) return FALSE;
    for (USHORT i = 0; i < count; i++) {
        n256->children[idx[i]] = children[i];
    }
    n256->base.num_of_child = count;
    return TRUE;
}

// Build a chain of NODE4 internal nodes of given depth, with a single leaf at the end.
// depth = number of NODE4 internals. Returns TRUE on success.
// Result: *out_root -> NODE4 -> NODE4 -> ... (depth times) -> LEAF
STATIC BOOLEAN fd_build_deep_chain_node4(ART_NODE** out_root, USHORT depth)
{
    if (!out_root) return FALSE;
    ART_NODE* child = NULL;

    // create the terminal leaf first
    UCHAR last_key = 0x7A;
    ART_LEAF* lf = make_leaf(&last_key, 1, 0xFE);
    if (!lf) return FALSE;
    child = (ART_NODE*)SET_LEAF(lf);

    // build from tail to head
    for (USHORT d = 0; d < depth; d++) {
        ART_NODE4* n = fd_make_node4();
        if (!n) {
            // best-effort cleanup of the partial chain
            if (child && IS_LEAF(child)) {
                ART_LEAF* l2 = LEAF_RAW(child);
                free_leaf(&l2);
            }
            else if (child) {
                // walk and free internal nodes best-effort
                ART_NODE* cur = child;
                while (cur && !IS_LEAF(cur) && cur->type == NODE4) {
                    ART_NODE4* p = (ART_NODE4*)cur;
                    ART_NODE* nxt = p->children[0];
                    free_node(&cur);
                    cur = nxt;
                }
                if (cur && IS_LEAF(cur)) {
                    ART_LEAF* l2 = LEAF_RAW(cur);
                    free_leaf(&l2);
                }
            }
            return FALSE;
        }
        UCHAR k = 1;
        ART_NODE* ch = child;
        if (!fd_node4_set(n, &k, 1, &ch)) {
            free_node((ART_NODE**)&n);
            return FALSE;
        }
        child = (ART_NODE*)n;
    }

    *out_root = child;
    return TRUE;
}

// Free (best-effort) any tree built by helpers above (used when a test fails early).
STATIC VOID fd_free_all(ART_NODE** pref)
{
    if (!pref || !*pref) return;
    ART_NODE* n = *pref;
    if (IS_LEAF(n)) {
        ART_LEAF* l = LEAF_RAW(n);
        free_leaf(&l);
        *pref = NULL;
        return;
    }
    switch (n->type) {
    case NODE4: {
        ART_NODE4* p = (ART_NODE4*)n;
        for (USHORT i = 0; i < 4; i++) if (p->children[i]) { ART_NODE* c = p->children[i]; fd_free_all(&c); }
        break;
    }
    case NODE16: {
        ART_NODE16* p = (ART_NODE16*)n;
        for (USHORT i = 0; i < 16; i++) if (p->children[i]) { ART_NODE* c = p->children[i]; fd_free_all(&c); }
        break;
    }
    case NODE48: {
        ART_NODE48* p = (ART_NODE48*)n;
        for (USHORT i = 0; i < 48; i++) if (p->children[i]) { ART_NODE* c = p->children[i]; fd_free_all(&c); }
        break;
    }
    case NODE256: {
        ART_NODE256* p = (ART_NODE256*)n;
        for (USHORT i = 0; i < 256; i++) if (p->children[i]) { ART_NODE* c = p->children[i]; fd_free_all(&c); }
        break;
    }
    default: break;
    }
    free_node(pref);
}

// ===============================================================
// Test 1: Guards (NULLs / empty root) — should succeed no-op
// ===============================================================
BOOLEAN test_force_delete_all_iterative_guards()
{
    TEST_START("force_delete_all_iterative: guards");

    ULONG leaves = 111, nodes = 222;
    NTSTATUS st;

    // 1.1 NULL proot
#pragma warning(push)
#pragma warning(disable:6387)
    st = force_delete_all_iterative(&leaves, &nodes, NULL);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.1: NULL proot -> STATUS_SUCCESS");
    TEST_ASSERT(leaves == 111 && nodes == 222, "1.1b: counters unchanged");

    // 1.2 *proot == NULL
    ART_NODE* root = NULL;
    leaves = 5; nodes = 9;
    st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "1.2: empty root -> STATUS_SUCCESS");
    TEST_ASSERT(leaves == 5 && nodes == 9, "1.2b: counters unchanged");

    // 1.3 NULL leaf_count
#pragma warning(push)
#pragma warning(disable:6387)
    st = force_delete_all_iterative(NULL, &nodes, &root);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.3: NULL leaf_count -> STATUS_SUCCESS");

    // 1.4 NULL node_count
#pragma warning(push)
#pragma warning(disable:6387)
    st = force_delete_all_iterative(&leaves, NULL, &root);
#pragma warning(pop)
    TEST_ASSERT(NT_SUCCESS(st), "1.4: NULL node_count -> STATUS_SUCCESS");

    TEST_END("force_delete_all_iterative: guards");
    return TRUE;
}

// ===============================================================
// Test 2: Single leaf root
// ===============================================================
BOOLEAN test_force_delete_all_iterative_single_leaf()
{
    TEST_START("force_delete_all_iterative: single leaf");

    UCHAR k = 'a';
    ART_LEAF* lf = make_leaf(&k, 1, 0x11);
    TEST_ASSERT(lf != NULL, "2-pre: leaf alloc");

    ART_NODE* root = (ART_NODE*)SET_LEAF(lf);
    ULONG leaves = 0, nodes = 0;

    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "2.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 1 && nodes == 1, "2.2: counts (1 leaf, 1 node)");
    TEST_ASSERT(root == NULL, "2.3: root cleared");

    TEST_END("force_delete_all_iterative: single leaf");
    return TRUE;
}

// ===============================================================
// Test 3: NODE4 with two leaves
// ===============================================================
BOOLEAN test_force_delete_all_iterative_node4_simple()
{
    TEST_START("force_delete_all_iterative: NODE4 simple");

    ART_NODE4* n4 = fd_make_node4();
    TEST_ASSERT(n4, "3-pre: NODE4 alloc");

    UCHAR kb[2] = { 1, 3 };
    ART_LEAF* l0 = make_leaf(&kb[0], 1, 0xA);
    ART_LEAF* l1 = make_leaf(&kb[1], 1, 0xB);
    TEST_ASSERT(l0 && l1, "3-pre: leaves");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(fd_node4_set(n4, kb, 2, ch), "3-pre: wire");

    ART_NODE* root = (ART_NODE*)n4;
    ULONG leaves = 0, nodes = 0;

    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 2, "3.2: 2 leaves");
    TEST_ASSERT(nodes == 3, "3.3: total nodes == 3 (2 leaves + NODE4)");
    TEST_ASSERT(root == NULL, "3.4: root cleared");

    TEST_END("force_delete_all_iterative: NODE4 simple");
    return TRUE;
}

// ===============================================================
// Test 4: NODE16 with three leaves
// ===============================================================
BOOLEAN test_force_delete_all_iterative_node16_three()
{
    TEST_START("force_delete_all_iterative: NODE16 three");

    ART_NODE16* n16 = fd_make_node16();
    TEST_ASSERT(n16, "4-pre: NODE16 alloc");

    UCHAR kb[3] = { 2, 4, 6 };
    ART_LEAF* l0 = make_leaf(&kb[0], 1, 0x10);
    ART_LEAF* l1 = make_leaf(&kb[1], 1, 0x20);
    ART_LEAF* l2 = make_leaf(&kb[2], 1, 0x30);
    TEST_ASSERT(l0 && l1 && l2, "4-pre: leaves");

    ART_NODE* ch[3] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1), (ART_NODE*)SET_LEAF(l2) };
    TEST_ASSERT(fd_node16_set(n16, kb, 3, ch), "4-pre: wire");

    ART_NODE* root = (ART_NODE*)n16;
    ULONG leaves = 0, nodes = 0;

    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 3, "4.2: 3 leaves");
    TEST_ASSERT(nodes == 4, "4.3: total nodes == 4 (3 leaves + NODE16)");
    TEST_ASSERT(root == NULL, "4.4: root cleared");

    TEST_END("force_delete_all_iterative: NODE16 three");
    return TRUE;
}

// ===============================================================
// Test 5: NODE48 sparse map (two leaves)
// ===============================================================
BOOLEAN test_force_delete_all_iterative_node48_sparse()
{
    TEST_START("force_delete_all_iterative: NODE48 sparse");

    ART_NODE48* n48 = fd_make_node48();
    TEST_ASSERT(n48, "5-pre: NODE48 alloc");

    UCHAR keys[2] = { 7, 200 };
    ART_LEAF* l0 = make_leaf(&keys[0], 1, 0xAA);
    ART_LEAF* l1 = make_leaf(&keys[1], 1, 0xBB);
    TEST_ASSERT(l0 && l1, "5-pre: leaves");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(l0), (ART_NODE*)SET_LEAF(l1) };
    TEST_ASSERT(fd_node48_map(n48, keys, 2, ch), "5-pre: map");

    ART_NODE* root = (ART_NODE*)n48;
    ULONG leaves = 0, nodes = 0;
    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 2, "5.2: 2 leaves");
    TEST_ASSERT(nodes == 3, "5.3: total nodes == 3 (2 leaves + NODE48)");
    TEST_ASSERT(root == NULL, "5.4: root cleared");

    TEST_END("force_delete_all_iterative: NODE48 sparse");
    return TRUE;
}

// ===============================================================
// Test 6: NODE256 mixed (two direct leaves + inner NODE4 -> one leaf)
// ===============================================================
BOOLEAN test_force_delete_all_iterative_node256_mixed()
{
    TEST_START("force_delete_all_iterative: NODE256 mixed");

    ART_NODE256* n256 = fd_make_node256();
    TEST_ASSERT(n256, "6-pre: NODE256 alloc");

    UCHAR idx[3] = { 0, 255, 100 }; // 100 -> internal NODE4
    ART_LEAF* l0 = make_leaf(&idx[0], 1, 0x01);
    ART_LEAF* l1 = make_leaf(&idx[1], 1, 0x02);
    TEST_ASSERT(l0 && l1, "6-pre: top leaves");

    ART_NODE4* inner = fd_make_node4();
    TEST_ASSERT(inner, "6-pre: inner NODE4");
    UCHAR subk = 5;
    ART_LEAF* ls = make_leaf(&subk, 1, 0x33);
    TEST_ASSERT(ls, "6-pre: inner leaf");

    ART_NODE* ich = (ART_NODE*)SET_LEAF(ls);
    TEST_ASSERT(fd_node4_set(inner, &subk, 1, &ich), "6-pre: inner wire");

    ART_NODE* top_children[3] = {
        (ART_NODE*)SET_LEAF(l0),
        (ART_NODE*)SET_LEAF(l1),
        (ART_NODE*)inner
    };
    TEST_ASSERT(fd_node256_set(n256, idx, 3, top_children), "6-pre: set");

    ART_NODE* root = (ART_NODE*)n256;
    ULONG leaves = 0, nodes = 0;

    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 3, "6.2: 3 leaves");
    TEST_ASSERT(nodes == 5, "6.3: total nodes == 5 (3 leaves + NODE4 + NODE256)");
    TEST_ASSERT(root == NULL, "6.4: root cleared");

    TEST_END("force_delete_all_iterative: NODE256 mixed");
    return TRUE;
}

// ===============================================================
// Test 7: Deep chain (> initial stack cap) triggers dynamic stack growth
// ===============================================================
BOOLEAN test_force_delete_all_iterative_deep_chain_growth()
{
    TEST_START("force_delete_all_iterative: deep chain stack growth");

    ART_NODE* root = NULL;
    // Build depth greater than initial cap (64) to exercise stack resizing.
    const USHORT depth = 100;
    TEST_ASSERT(fd_build_deep_chain_node4(&root, depth), "7-pre: built deep chain");

    ULONG leaves = 0, nodes = 0;
    NTSTATUS st = force_delete_all_iterative(&leaves, &nodes, &root);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: STATUS_SUCCESS");
    TEST_ASSERT(leaves == 1, "7.2: exactly one leaf");
    TEST_ASSERT(nodes == (ULONG)(depth + 1), "7.3: internals + leaf == depth+1");
    TEST_ASSERT(root == NULL, "7.4: root cleared");

    TEST_END("force_delete_all_iterative: deep chain stack growth");
    return TRUE;
}

// ===============================================================
// Test 8: FI-only branches (allocation failure during stack growth)
// Note: requires fault injection on ExAllocatePool2 to simulate OOM.
// ===============================================================
BOOLEAN test_force_delete_all_iterative_fi_only_documented()
{
    TEST_START("force_delete_all_iterative: FI-only branches (documented)");
    LOG_MSG("[INFO] To test OOM during stack reallocation, a fault injector for ExAllocatePool2 is required.\n");
    LOG_MSG("[INFO] Expected behavior on OOM: function returns STATUS_INSUFFICIENT_RESOURCES and *proot remains non-NULL.\n");
    TEST_END("force_delete_all_iterative: FI-only branches (documented)");
    return TRUE;
}

// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_force_delete_all_iterative_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting force_delete_all_iterative() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_force_delete_all_iterative_guards())             all = FALSE; // 1
    if (!test_force_delete_all_iterative_single_leaf())        all = FALSE; // 2
    if (!test_force_delete_all_iterative_node4_simple())       all = FALSE; // 3
    if (!test_force_delete_all_iterative_node16_three())       all = FALSE; // 4
    if (!test_force_delete_all_iterative_node48_sparse())      all = FALSE; // 5
    if (!test_force_delete_all_iterative_node256_mixed())      all = FALSE; // 6
    if (!test_force_delete_all_iterative_deep_chain_growth())  all = FALSE; // 7
    if (!test_force_delete_all_iterative_fi_only_documented()) all = FALSE; // 8 (doc)

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL force_delete_all_iterative() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME force_delete_all_iterative() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif
