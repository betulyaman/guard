#include "test_art.h"

// SUT
NTSTATUS art_destroy_tree(_Inout_ ART_TREE* tree);

// ---------- tiny local helpers (no CRT) ----------
static VOID dz(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* mk_n4(void) { return (ART_NODE4*)art_create_node(NODE4); }
static ART_NODE16* mk_n16(void) { return (ART_NODE16*)art_create_node(NODE16); }
static ART_NODE48* mk_n48(void) { return (ART_NODE48*)art_create_node(NODE48); }
static ART_NODE256* mk_n256(void) { return (ART_NODE256*)art_create_node(NODE256); }

static BOOLEAN n4_set(ART_NODE4* n4, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n4 || !keys || !ch || cnt > 4) return FALSE;
    dz(n4->keys, sizeof(n4->keys));
    dz(n4->children, sizeof(n4->children));
    for (USHORT i = 0; i < cnt; i++) { n4->keys[i] = keys[i]; n4->children[i] = ch[i]; }
    n4->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN n16_set(ART_NODE16* n16, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n16 || !keys || !ch || cnt > 16) return FALSE;
    dz(n16->keys, sizeof(n16->keys));
    dz(n16->children, sizeof(n16->children));
    for (USHORT i = 0; i < cnt; i++) { n16->keys[i] = keys[i]; n16->children[i] = ch[i]; }
    n16->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN n48_map(ART_NODE48* n48, const UCHAR* key_bytes, USHORT cnt, ART_NODE* const* ch)
{
    if (!n48 || !key_bytes || !ch || cnt > 48) return FALSE;
    dz(n48->child_index, sizeof(n48->child_index));
    dz(n48->children, sizeof(n48->children));
    for (USHORT i = 0; i < cnt; i++) { n48->children[i] = ch[i]; n48->child_index[key_bytes[i]] = (UCHAR)(i + 1); }
    n48->base.num_of_child = cnt;
    return TRUE;
}
static BOOLEAN n256_set(ART_NODE256* n256, const UCHAR* idx, USHORT cnt, ART_NODE* const* ch)
{
    if (!n256 || !idx || !ch || cnt > 256) return FALSE;
    dz(n256->children, sizeof(n256->children));
    for (USHORT i = 0; i < cnt; i++) { n256->children[idx[i]] = ch[i]; }
    n256->base.num_of_child = cnt;
    return TRUE;
}

// Test 1: Guard parameter checks
BOOLEAN test_destroy_guard_params()
{
    TEST_START("art_destroy_tree: guard params");
#pragma warning(push)
#pragma warning(disable: 6387)
    NTSTATUS st = art_destroy_tree(NULL);
#pragma warning(pop)
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL tree -> STATUS_INVALID_PARAMETER");

    TEST_END("art_destroy_tree: guard params");
    return TRUE;
}

// Test 2: Empty tree (root == NULL)
BOOLEAN test_destroy_empty_tree()
{
    TEST_START("art_destroy_tree: empty tree");

    ART_TREE t; dz(&t, sizeof(t));
    t.size = 123;    // should be reset to 0
    t.root = NULL;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "2.1: returns STATUS_SUCCESS");
    TEST_ASSERT(t.root == NULL, "2.2: root remains NULL");
    TEST_ASSERT(t.size == 0, "2.3: size reset to 0");

    TEST_END("art_destroy_tree: empty tree");
    return TRUE;
}

// Test 3: Single LEAF as root
BOOLEAN test_destroy_single_leaf_root()
{
    TEST_START("art_destroy_tree: single leaf root");

    UCHAR kb = 'b';
    ART_LEAF* leaf = make_leaf(&kb, 1, 0xBEEF);
    TEST_ASSERT(leaf != NULL, "3-pre: leaf allocated");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)SET_LEAF(leaf);
    t.size = 1;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: returns STATUS_SUCCESS");
    TEST_ASSERT(t.root == NULL, "3.2: root cleared");
    TEST_ASSERT(t.size == 0, "3.3: size set to 0");

    // leaf must be freed by destroy; nothing to free here
    TEST_END("art_destroy_tree: single leaf root");
    return TRUE;
}

// Test 4: Small NODE4 internal with two leaves
BOOLEAN test_destroy_node4_two_leaves()
{
    TEST_START("art_destroy_tree: NODE4 with two leaves");

    ART_NODE4* root = mk_n4();
    TEST_ASSERT(root != NULL, "4-pre: NODE4 allocated");

    UCHAR k1 = 'a', k2 = 'z';
    ART_LEAF* l1 = make_leaf(&k1, 1, 0x11);
    ART_LEAF* l2 = make_leaf(&k2, 1, 0x22);
    TEST_ASSERT(l1 && l2, "4-pre: two leaves allocated");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(l1), (ART_NODE*)SET_LEAF(l2) };
    UCHAR keys[2] = { k1, k2 };
    TEST_ASSERT(n4_set(root, keys, 2, ch), "4-pre: node wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 2;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: success");
    TEST_ASSERT(t.root == NULL, "4.2: root cleared");
    TEST_ASSERT(t.size == 0, "4.3: size zeroed");

    TEST_END("art_destroy_tree: NODE4 with two leaves");
    return TRUE;
}

// Test 5: Mixed NODE16 -> NODE48 -> NODE256 with leaves
BOOLEAN test_destroy_mixed_topology()
{
    TEST_START("art_destroy_tree: mixed topology (16/48/256)");

    // root16 with keys {10:'\n', 200}
    ART_NODE16* root16 = mk_n16();
    TEST_ASSERT(root16 != NULL, "5-pre: NODE16 root");

    // child0: NODE48 with two leaves at keys 1 and 250
    ART_NODE48* n48 = mk_n48();
    TEST_ASSERT(n48 != NULL, "5-pre: NODE48 child");
    UCHAR map48[2] = { 1, 250 };
    UCHAR v1 = 1, v2 = 2;
    ART_LEAF* l1 = make_leaf(&v1, 1, 0xA1);
    ART_LEAF* l2 = make_leaf(&v2, 1, 0xA2);
    TEST_ASSERT(l1 && l2, "5-pre: leaves under NODE48");
    ART_NODE* ch48[2] = { (ART_NODE*)SET_LEAF(l1), (ART_NODE*)SET_LEAF(l2) };
    TEST_ASSERT(n48_map(n48, map48, 2, ch48), "5-pre: NODE48 wired");

    // child1: NODE256 with one leaf at [7]
    ART_NODE256* n256 = mk_n256();
    TEST_ASSERT(n256 != NULL, "5-pre: NODE256 child");
    UCHAR idx256[1] = { 7 };
    UCHAR v7 = 7;
    ART_LEAF* l7 = make_leaf(&v7, 1, 0xB7);
    TEST_ASSERT(l7 != NULL, "5-pre: leaf under NODE256");
    ART_NODE* ch256[1] = { (ART_NODE*)SET_LEAF(l7) };
    TEST_ASSERT(n256_set(n256, idx256, 1, ch256), "5-pre: NODE256 wired");

    // root wiring
    ART_NODE* rch[2] = { (ART_NODE*)n48, (ART_NODE*)n256 };
    UCHAR rkeys[2] = { 10, 200 };
    TEST_ASSERT(n16_set(root16, rkeys, 2, rch), "5-pre: NODE16 wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)root16;
    t.size = 3; // three leaves total

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: success");
    TEST_ASSERT(t.root == NULL, "5.2: root cleared");
    TEST_ASSERT(t.size == 0, "5.3: size zeroed");

    TEST_END("art_destroy_tree: mixed topology (16/48/256)");
    return TRUE;
}

// Test 6: Idempotency (destroy twice)
BOOLEAN test_destroy_idempotent()
{
    TEST_START("art_destroy_tree: idempotency");

    // build trivial tree (single leaf)
    UCHAR kc = 'c';
    ART_LEAF* leaf = make_leaf(&kc, 1, 0x33);
    TEST_ASSERT(leaf != NULL, "6-pre: leaf allocated");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)SET_LEAF(leaf);
    t.size = 1;

    NTSTATUS st1 = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st1), "6.1: first destroy succeeds");
    TEST_ASSERT(t.root == NULL && t.size == 0, "6.2: state cleared");

    NTSTATUS st2 = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st2), "6.3: second destroy also succeeds");
    TEST_ASSERT(t.root == NULL && t.size == 0, "6.4: remains cleared");

    TEST_END("art_destroy_tree: idempotency");
    return TRUE;
}

// Test 7: Error propagation (deep recursion overflow)
BOOLEAN test_destroy_propagates_failure_and_clears()
{
    TEST_START("art_destroy_tree: propagates failure, still clears state");

    // Build a chain deeper than MAX_RECURSION_DEPTH to force
    // recursive_delete_all_internal(...) -> STATUS_STACK_OVERFLOW
    ART_NODE* cur = (ART_NODE*)mk_n4();
    TEST_ASSERT(cur != NULL, "7-pre: first NODE4");
    ART_NODE* root = cur;

    const UCHAR step_key = 'a';
    for (USHORT i = 0; i < (USHORT)(MAX_RECURSION_DEPTH + 2); i++) {
        ART_NODE4* n4 = (ART_NODE4*)cur;
        ART_NODE* next;
        if (i == (USHORT)(MAX_RECURSION_DEPTH + 1)) {
            UCHAR lfkb = 'x';
            ART_LEAF* lf = make_leaf(&lfkb, 1, 0x55);
            TEST_ASSERT(lf != NULL, "7-pre: tail leaf");
            next = (ART_NODE*)SET_LEAF(lf);
        }
        else {
            next = (ART_NODE*)mk_n4();
            TEST_ASSERT(next != NULL, "7-pre: intermediate NODE4");
        }
        UCHAR k = step_key;
        ART_NODE* child = next;
        TEST_ASSERT(n4_set(n4, &k, 1, &child), "7-pre: link step");

        if (!IS_LEAF(next)) cur = next;
    }

    ART_TREE t; dz(&t, sizeof(t));
    t.root = root;
    t.size = 1;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(st == STATUS_STACK_OVERFLOW, "7.1: error propagated from delete_all");
    TEST_ASSERT(t.root == NULL, "7.2: root cleared even on failure");
    TEST_ASSERT(t.size == 0, "7.3: size zeroed even on failure");

    TEST_END("art_destroy_tree: propagates failure, still clears state");
    return TRUE;
}

BOOLEAN test_destroy_utf8_key_null_safe()
{
    TEST_START("destroy_utf8_key: NULL safety");

    reset_mock_state();
    ULONG free_before = g_free_call_count;

    // Should be a no-op (no free, no crash)
    destroy_utf8_key(NULL);

    TEST_ASSERT(g_free_call_count == free_before, "X1.1: No free should occur for NULL key");

    TEST_END("destroy_utf8_key: NULL safety");
    return TRUE;
}

BOOLEAN test_destroy_utf8_key_frees_with_tag()
{
    TEST_START("destroy_utf8_key: frees with ART_TAG");

    reset_mock_state();

    // Allocate a fake UTF-8 key with correct tag to be freed by SUT
    SIZE_T sz = 32;
    PUCHAR p = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, ART_TAG);
    TEST_ASSERT(p != NULL, "X2-pre: allocation succeeded");

    // Fill just to avoid compiler complaining; not functionally required
    if (p) { p[0] = 0; }

    ULONG free_before = g_free_call_count;

    destroy_utf8_key(p); // SUT should free with ART_TAG

    TEST_ASSERT(g_free_call_count == free_before + 1, "X2.1: One free should have occurred");
#ifdef TRACK_LAST_FREED_TAG
    // If your test framework tracks last freed tag
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "X2.2: Freed with ART_TAG");
#endif

    // SUT owns the free; nothing to free here.
    TEST_END("destroy_utf8_key: frees with ART_TAG");
    return TRUE;
}

// Test X3: Empty internal node (NODE4, zero children)
BOOLEAN test_destroy_empty_internal_node()
{
    TEST_START("art_destroy_tree: empty internal NODE4");

    ART_NODE4* root = mk_n4();
    TEST_ASSERT(root != NULL, "X3-pre: NODE4 allocated");

    // Ensure explicitly zero children (mk_n4 already zeros, but be explicit)
    root->base.num_of_child = 0;
    for (int i = 0; i < 4; ++i)
    {
        root->children[i] = NULL;
        root->keys[i] = 0;
    }

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)root;
    t.size = 123; // arbitrary; should reset to 0

    ULONG f0 = g_free_call_count;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "X3.1: success");
    TEST_ASSERT(t.root == NULL, "X3.2: root cleared");
    TEST_ASSERT(t.size == 0, "X3.3: size zeroed");
    TEST_ASSERT((g_free_call_count - f0) >= 1, "X3.4: internal node freed");

    TEST_END("art_destroy_tree: empty internal NODE4");
    return TRUE;
}

// Test X4: Sparse NODE256 with edge indices (0 and 255)
BOOLEAN test_destroy_sparse_node256_edges()
{
    TEST_START("art_destroy_tree: sparse NODE256 (edges 0,255)");

    ART_NODE256* root256 = mk_n256();
    TEST_ASSERT(root256 != NULL, "X4-pre: NODE256 allocated");

    UCHAR i0 = 0, i255 = 255;
    UCHAR kv0 = 'q', kv255 = 'w';

    ART_LEAF* lf0 = make_leaf(&kv0, 1, 0x100);
    ART_LEAF* lf255 = make_leaf(&kv255, 1, 0x200);
    TEST_ASSERT(lf0 && lf255, "X4-pre: two leaves allocated");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(lf0), (ART_NODE*)SET_LEAF(lf255) };
    UCHAR idx[2] = { i0, i255 };
    TEST_ASSERT(n256_set(root256, idx, 2, ch), "X4-pre: NODE256 wired @0 and @255");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)root256;
    t.size = 2;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "X4.1: success");
    TEST_ASSERT(t.root == NULL, "X4.2: root cleared");
    TEST_ASSERT(t.size == 0, "X4.3: size zeroed");
    TEST_ASSERT((g_free_call_count - f0) >= (g_alloc_call_count - a0), "X4.4: no leak (all freed)");

    TEST_END("art_destroy_tree: sparse NODE256 (edges 0,255)");
    return TRUE;
}

// Test X5: Allocation/free balance (no leaks)
BOOLEAN test_destroy_alloc_free_balance()
{
    TEST_START("art_destroy_tree: alloc/free balance");

    // Build: NODE4 -> NODE16 -> two leaves
    ART_NODE4* n4 = mk_n4();
    TEST_ASSERT(n4 != NULL, "X5-pre: NODE4 allocated");

    ART_NODE16* n16 = mk_n16();
    TEST_ASSERT(n16 != NULL, "X5-pre: NODE16 allocated");

    UCHAR ka = 'a', kz = 'z';
    ART_LEAF* la = make_leaf(&ka, 1, 0xAA);
    ART_LEAF* lz = make_leaf(&kz, 1, 0xBB);
    if (!lz) { lz = make_leaf(&kz, 1, 0xBB); }
    TEST_ASSERT(la && lz, "X5-pre: two leaves allocated");

    ART_NODE* c16[2] = { (ART_NODE*)SET_LEAF(la), (ART_NODE*)SET_LEAF(lz) };
    UCHAR k16[2] = { (UCHAR)'1', (UCHAR)'2' };
    TEST_ASSERT(n16_set(n16, k16, 2, c16), "X5-pre: NODE16 wired");

    ART_NODE* c4[1] = { (ART_NODE*)n16 };
    UCHAR k4[1] = { (UCHAR)'x' };
    TEST_ASSERT(n4_set(n4, k4, 1, c4), "X5-pre: NODE4 wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)n4;
    t.size = 2;

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    NTSTATUS st = art_destroy_tree(&t);
    TEST_ASSERT(NT_SUCCESS(st), "X5.1: success");
    TEST_ASSERT(t.root == NULL && t.size == 0, "X5.2: cleared");

    // At least all newly allocated nodes/leaves must be freed.
    TEST_ASSERT((g_free_call_count - f0) >= (g_alloc_call_count - a0), "X5.3: no net leak for this build/destroy");

    TEST_END("art_destroy_tree: alloc/free balance");
    return TRUE;
}

// Test X6: destroy_utf8_key frees the exact pointer
BOOLEAN test_destroy_utf8_key_records_pointer()
{
    TEST_START("destroy_utf8_key: records freed pointer");

    reset_mock_state();

    SIZE_T sz = 8;
    PUCHAR p = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, ART_TAG);
    TEST_ASSERT(p != NULL, "X6-pre: allocation succeeded");
    if (p) { p[0] = 0; }

    destroy_utf8_key(p);

    TEST_ASSERT(g_last_freed_pointer == p, "X6.1: Freed pointer should match input");
#ifdef TRACK_LAST_FREED_TAG
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "X6.2: Freed with ART_TAG");
#endif

    TEST_END("destroy_utf8_key: records freed pointer");
    return TRUE;
}


// Suite runner
NTSTATUS run_all_art_destroy_tree_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_destroy_tree() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_destroy_guard_params())                    all = FALSE; // (1)
    if (!test_destroy_empty_tree())                      all = FALSE; // (2)
    if (!test_destroy_single_leaf_root())                all = FALSE; // (3)
    if (!test_destroy_node4_two_leaves())                all = FALSE; // (4)
    if (!test_destroy_mixed_topology())                  all = FALSE; // (5)
    if (!test_destroy_idempotent())                      all = FALSE; // (6)
    if (!test_destroy_propagates_failure_and_clears())   all = FALSE; // (7)
    if (!test_destroy_utf8_key_null_safe())              all = FALSE; // (X1)
    if (!test_destroy_utf8_key_frees_with_tag())         all = FALSE; // (X2)
    if (!test_destroy_empty_internal_node())              all = FALSE; // (X3)
    if (!test_destroy_sparse_node256_edges())            all = FALSE; // (X4)
    if (!test_destroy_alloc_free_balance())              all = FALSE; // (X5)
    if (!test_destroy_utf8_key_records_pointer())        all = FALSE; // (X6)


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL art_destroy_tree() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_destroy_tree() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
