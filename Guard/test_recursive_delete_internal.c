#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC ART_LEAF* recursive_delete_internal(_In_ ART_NODE* node,
    _Inout_ ART_NODE** ref,
    _In_reads_bytes_(key_length) CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ USHORT depth,
    _In_ USHORT recursion_depth);

// ---------- tiny helpers (kernel-safe) ----------
static VOID t_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

static ART_NODE4* t_make_node4_with_two_leaves(ART_NODE** out_ref,
    UCHAR kA, UCHAR kB,
    ART_LEAF** out_lA,
    ART_LEAF** out_lB)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

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

static ART_NODE4* t_make_node4_with_prefix_and_leaf(ART_NODE** out_ref,
    UCHAR prefixByte,
    UCHAR childKey,
    ART_LEAF** out_leaf)
{
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return NULL;
    n4->base.type = NODE4;
    n4->base.num_of_child = 0;
    n4->base.prefix_length = 1;
    t_zero(n4->base.prefix, sizeof(n4->base.prefix));
    n4->base.prefix[0] = prefixByte;

    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));

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

static ART_NODE4* t_make_two_level_internal_then_leaf(ART_NODE** out_ref,
    UCHAR pfx, UCHAR midKey, UCHAR lastKey,
    ART_LEAF** out_leaf)
{
    // root with prefix pfx and child internal NODE4 at key midKey; that child has a leaf at lastKey
    ART_NODE4* root = (ART_NODE4*)art_create_node(NODE4);
    if (!root) return NULL;
    root->base.type = NODE4;
    root->base.prefix_length = 1;
    root->base.num_of_child = 0;
    t_zero(root->base.prefix, sizeof(root->base.prefix));
    root->base.prefix[0] = pfx;
    t_zero(root->keys, sizeof(root->keys));
    t_zero(root->children, sizeof(root->children));

    ART_NODE4* mid = (ART_NODE4*)art_create_node(NODE4);
    if (!mid) { free_node((ART_NODE**)&root); return NULL; }
    mid->base.type = NODE4;
    mid->base.num_of_child = 0;
    mid->base.prefix_length = 0;
    t_zero(mid->keys, sizeof(mid->keys));
    t_zero(mid->children, sizeof(mid->children));

    UCHAR fullKey[3] = { pfx, midKey, lastKey };
    ART_LEAF* lf = make_leaf(fullKey, 3, 0xDD);
    if (!lf) {
        free_node((ART_NODE**)&mid);
        free_node((ART_NODE**)&root);
        return NULL;
    }

    // mid node: one child
    mid->keys[0] = lastKey;
    mid->children[0] = (ART_NODE*)SET_LEAF(lf);
    mid->base.num_of_child = 1;

    // root: one child
    root->keys[0] = midKey;
    root->children[0] = (ART_NODE*)mid;
    root->base.num_of_child = 1;

    if (out_ref) *out_ref = (ART_NODE*)root;
    if (out_leaf) *out_leaf = lf;
    return root;
}

static VOID t_free_tree_best_effort(ART_NODE** pref)
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
                t_free_tree_best_effort(&sub);
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
                t_free_tree_best_effort(&sub);
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
                t_free_tree_best_effort(&sub);
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
                t_free_tree_best_effort(&sub);
            }
        }
        break;
    }
    default: break;
    }

    free_node(pref); // sets *pref = NULL
}

// ===============================================================
// Test 1: Guard checks & basic invalids
// ===============================================================
BOOLEAN test_recursive_delete_internal_guards()
{
    TEST_START("recursive_delete_internal: guard checks");

    reset_mock_state();

    UCHAR keyB[1] = { 'b' };
    ART_NODE* ref = NULL;

#pragma warning(push)
#pragma warning(disable: 6387)
    ART_LEAF* out = recursive_delete_internal(NULL, NULL, NULL, 0, 0, 0);
#pragma warning(pop)
    TEST_ASSERT(out == NULL, "1.1: all NULL rejected");

    out = recursive_delete_internal(NULL, &ref, keyB, 1, 0, 0);
    TEST_ASSERT(out == NULL, "1.2: NULL node");

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "1-pre: created node");
    ref = (ART_NODE*)n4;

    out = recursive_delete_internal((ART_NODE*)n4, NULL, keyB, 1, 0, 0);
    TEST_ASSERT(out == NULL, "1.3: NULL ref");

#pragma warning(push)
#pragma warning(disable: 6387)
    out = recursive_delete_internal((ART_NODE*)n4, &ref, NULL, 1, 0, 0);
#pragma warning(pop)
    TEST_ASSERT(out == NULL, "1.4: NULL key");

    out = recursive_delete_internal((ART_NODE*)n4, &ref, keyB, 0, 0, 0);
    TEST_ASSERT(out == NULL, "1.5: key_length=0");

    out = recursive_delete_internal((ART_NODE*)n4, &ref, keyB, 1, 1, 0);
    TEST_ASSERT(out == NULL, "1.6: depth >= key_length");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: guard checks");
    return TRUE;
}

// ===============================================================
// Test 2: Leaf node – match , remove and return leaf
// ===============================================================
BOOLEAN test_recursive_delete_internal_leaf_match()
{
    TEST_START("recursive_delete_internal: leaf match");

    reset_mock_state();

    UCHAR keyA[1] = { 'a' };
    ART_LEAF* lf = make_leaf(keyA, 1, 0x11);
    TEST_ASSERT(lf != NULL, "2-pre: leaf created");

    ART_NODE* encoded = (ART_NODE*)SET_LEAF(lf);
    ART_NODE* ref = encoded;

    ART_LEAF* out = recursive_delete_internal(encoded, &ref, keyA, 1, 0, 0);
    TEST_ASSERT(out == lf, "2.1: returns the matched leaf");
    TEST_ASSERT(ref == NULL, "2.2: ref cleared for removed leaf");

    if (out) free_leaf(&out);

    TEST_END("recursive_delete_internal: leaf match");
    return TRUE;
}

// ===============================================================
// Test 3: Leaf node – not match , return NULL, no changes
// ===============================================================
BOOLEAN test_recursive_delete_internal_leaf_no_match()
{
    TEST_START("recursive_delete_internal: leaf no match");

    reset_mock_state();

    UCHAR keyA[1] = { 'a' };
    UCHAR keyB[1] = { 'b' };
    ART_LEAF* lf = make_leaf(keyA, 1, 0x22);
    TEST_ASSERT(lf != NULL, "3-pre: leaf created");

    ART_NODE* encoded = (ART_NODE*)SET_LEAF(lf);
    ART_NODE* ref = encoded;

    ART_LEAF* out = recursive_delete_internal(encoded, &ref, keyB, 1, 0, 0);
    TEST_ASSERT(out == NULL, "3.1: returns NULL when not matching leaf");
    TEST_ASSERT(ref == encoded, "3.2: ref unchanged");

    free_leaf(&lf);

    TEST_END("recursive_delete_internal: leaf no match");
    return TRUE;
}

// ===============================================================
// Test 4: Internal node with prefix – mismatch , return NULL
// ===============================================================
BOOLEAN test_recursive_delete_internal_prefix_mismatch()
{
    TEST_START("recursive_delete_internal: prefix mismatch");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* n4 = t_make_node4_with_prefix_and_leaf(&ref, 'x', 'a', &leaf);
    TEST_ASSERT(n4 != NULL, "4-pre: NODE4 with prefix created");

    UCHAR wrongKey[2] = { 'y', 'a' };
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, wrongKey, 2, 0, 0);
    TEST_ASSERT(out == NULL, "4.1: returns NULL on prefix mismatch");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: prefix mismatch");
    return TRUE;
}

// ===============================================================
// Test 5: Internal node with prefix – match, then delete leaf child
// ===============================================================
BOOLEAN test_recursive_delete_internal_prefix_match_delete()
{
    TEST_START("recursive_delete_internal: prefix match -> delete");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* n4 = t_make_node4_with_prefix_and_leaf(&ref, 'x', 'a', &leaf);
    TEST_ASSERT(n4 != NULL, "5-pre: NODE4 with prefix created");

    UCHAR fullKey[2] = { 'x', 'a' };
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, fullKey, 2, 0, 0);
    TEST_ASSERT(out == leaf, "5.1: returned removed leaf");
    if (out) free_leaf(&out);

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: prefix match -> delete");
    return TRUE;
}

// ===============================================================
// Test 6: Internal node – find_child returns NULL , return NULL
// ===============================================================
BOOLEAN test_recursive_delete_internal_missing_child()
{
    TEST_START("recursive_delete_internal: missing child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lA = NULL;
    ART_LEAF* lB = NULL;
    ART_NODE4* n4 = t_make_node4_with_two_leaves(&ref, 'a', 'b', &lA, &lB);
    TEST_ASSERT(n4 != NULL, "6-pre: NODE4(2) created");

    UCHAR keyC[1] = { 'c' }; // no 'c' child
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, keyC, 1, 0, 0);
    TEST_ASSERT(out == NULL, "6.1: returns NULL when child missing");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: missing child");
    return TRUE;
}

// ===============================================================
// Test 7: Successful delete at root (internal -> leaf child)
// ===============================================================
BOOLEAN test_recursive_delete_internal_delete_root_child()
{
    TEST_START("recursive_delete_internal: delete root child");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* lA = NULL;
    ART_LEAF* lB = NULL;
    ART_NODE4* n4 = t_make_node4_with_two_leaves(&ref, 'a', 'b', &lA, &lB);
    TEST_ASSERT(n4 != NULL, "7-pre: NODE4(2) created");

    UCHAR key[1] = { 'a' };
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, key, 1, 0, 0);
    TEST_ASSERT(out != NULL, "7.1: deletion succeeded, leaf returned");
    if (out) free_leaf(&out);

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: delete root child");
    return TRUE;
}

// ===============================================================
// Test 8: Two-level recursion – delete deeper leaf
// ===============================================================
BOOLEAN test_recursive_delete_internal_two_level_delete()
{
    TEST_START("recursive_delete_internal: two-level delete");

    reset_mock_state();

    ART_NODE* ref = NULL;
    ART_LEAF* leaf = NULL;
    ART_NODE4* root = t_make_two_level_internal_then_leaf(&ref, 'p', 'q', 'r', &leaf);
    TEST_ASSERT(root != NULL, "8-pre: two-level tree created");

    UCHAR key[3] = { 'p','q','r' };
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)root, &ref, key, 3, 0, 0);
    TEST_ASSERT(out == leaf, "8.1: returned the deeper leaf");
    if (out) free_leaf(&out);

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: two-level delete");
    return TRUE;
}

// ===============================================================
// Test 9: Recursion depth ceiling
// ===============================================================
BOOLEAN test_recursive_delete_internal_recursion_limit()
{
    TEST_START("recursive_delete_internal: recursion depth limit");

    reset_mock_state();

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "9-pre: node created");
    ART_NODE* ref = (ART_NODE*)n4;

    UCHAR key[1] = { 'z' };

    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, key, 1, 0,
        (USHORT)(MAX_RECURSION_DEPTH + 1));
    TEST_ASSERT(out == NULL, "9.1: returns NULL when recursion depth exceeded");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: recursion depth limit");
    return TRUE;
}

// ===============================================================
// Extra Test A: Terminator edge deletion (depth == key_length)
// ===============================================================
BOOLEAN test_recursive_delete_internal_terminator_delete()
{
    TEST_START("recursive_delete_internal: terminator edge delete");

    reset_mock_state();

    // Build NODE4 with prefix "ab" and a terminator leaf under key byte 0
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "A-pre: created NODE4");
    n4->base.type = NODE4;
    n4->base.prefix_length = 2;
    n4->base.num_of_child = 1;
    n4->base.prefix[0] = 'a';
    n4->base.prefix[1] = 'b';

    // Terminator leaf for exact key "ab"
    UCHAR k_ab[2] = { 'a','b' };
    ART_LEAF* lf = make_leaf(k_ab, 2, 0xEF);
    TEST_ASSERT(lf != NULL, "A-pre: created leaf");

    // Put it at key byte 0
    t_zero(n4->keys, sizeof(n4->keys));
    t_zero(n4->children, sizeof(n4->children));
    n4->keys[0] = 0;                             // terminator edge
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);

    ART_NODE* ref = (ART_NODE*)n4;

    // Delete key "ab"
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, k_ab, /*key_len*/2, /*depth*/0, /*rec_depth*/0);
    TEST_ASSERT(out == lf, "A.1: returns the terminator leaf");
    if (out) free_leaf(&out);

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: terminator edge delete");
    return TRUE;
}

// ===============================================================
// Extra Test B: Long-prefix (> MAX_PREFIX_LENGTH) validation & delete
// ===============================================================
BOOLEAN test_recursive_delete_internal_long_prefix_delete()
{
    TEST_START("recursive_delete_internal: long-prefix validation + delete");

    reset_mock_state();

    // Build NODE4 with a long prefix and one child leaf directly under next byte
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4 != NULL, "B-pre: created NODE4");
    n4->base.type = NODE4;
    n4->base.num_of_child = 1;

    // Set prefix_length to MAX_PREFIX_LENGTH + 3, with the first MAX_PREFIX_LENGTH bytes in prefix[]
    n4->base.prefix_length = (USHORT)(MAX_PREFIX_LENGTH + 3);
    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; i++) n4->base.prefix[i] = (UCHAR)('A' + (i % 26));

    // Child: edge byte after the prefix (call it 'x'), then a leaf representing the full key
    UCHAR edge = 'x';
    n4->keys[0] = edge;

    // Build the *full* key: MAX_PREFIX_LENGTH bytes (matching prefix), then 3 extra ('a','b','c'),
    // then the edge byte 'x', then a last byte 'Z' to make it a unique leaf key.
    const USHORT rem = 3;
    const USHORT total_prefix = (USHORT)(MAX_PREFIX_LENGTH + rem);
    const USHORT key_len = (USHORT)(total_prefix + 2); // + edge + last
    UCHAR* fullkey = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, key_len, ART_TAG);
    TEST_ASSERT(fullkey != NULL, "B-pre: allocated full key");

    for (USHORT i = 0; i < MAX_PREFIX_LENGTH; i++) fullkey[i] = (UCHAR)('A' + (i % 26));
    fullkey[MAX_PREFIX_LENGTH + 0] = 'a';
    fullkey[MAX_PREFIX_LENGTH + 1] = 'b';
    fullkey[MAX_PREFIX_LENGTH + 2] = 'c';
    fullkey[total_prefix + 0] = edge;
    fullkey[total_prefix + 1] = 'Z';

    ART_LEAF* lf = make_leaf(fullkey, key_len, 0x77);
    TEST_ASSERT(lf != NULL, "B-pre: leaf created");
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);

    ART_NODE* ref = (ART_NODE*)n4;

    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, fullkey, key_len, /*depth*/0, /*rec_depth*/0);
    TEST_ASSERT(out == lf, "B.1: returned matching leaf with long-prefix compare");
    if (out) free_leaf(&out);

    if (ref) t_free_tree_best_effort(&ref);
    ExFreePool2(fullkey, ART_TAG, NULL, 0);

    TEST_END("recursive_delete_internal: long-prefix validation + delete");
    return TRUE;
}

BOOLEAN test_recursive_delete_internal_key_shorter_than_prefix()
{
    TEST_START("recursive_delete_internal: key shorter than full logical prefix");

    reset_mock_state();

    ART_NODE* ref = NULL; ART_LEAF* leaf = NULL;
    // root prefix 'x', child 'y' altında leaf → efektif logical prefix "xy"
    ART_NODE4* n4 = t_make_node4_with_prefix_and_leaf(&ref, 'x', 'y', &leaf);
    TEST_ASSERT(n4 && leaf, "pre: node with prefix+leaf");

    UCHAR shortKey[1] = { 'x' }; // full logical prefix "xy" ile eşleşmiyor
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, shortKey, 1, 0, 0);
    TEST_ASSERT(out == NULL, "returns NULL on short key vs full logical prefix");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: key shorter than prefix");
    return TRUE;
}

BOOLEAN test_recursive_delete_internal_terminator_mismatch()
{
    TEST_START("recursive_delete_internal: terminator present but leaf mismatch");

    reset_mock_state();

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4, "pre: NODE4");
    n4->base.type = NODE4; n4->base.prefix_length = 2; n4->base.num_of_child = 1;
    n4->base.prefix[0] = 'a'; n4->base.prefix[1] = 'b';
    t_zero(n4->keys, sizeof(n4->keys)); t_zero(n4->children, sizeof(n4->children));

    UCHAR k_ab[2] = { 'a','b' };
    ART_LEAF* lf = make_leaf(k_ab, 2, 0xEF);
    TEST_ASSERT(lf, "leaf");
    n4->keys[0] = 0; // terminator
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);

    ART_NODE* ref = (ART_NODE*)n4;

    UCHAR k_ac[2] = { 'a','c' }; // aynı uzunluk ama içerik farklı
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, k_ac, 2, 0, 0);
    TEST_ASSERT(out == NULL, "no delete on terminator mismatch");
    TEST_ASSERT(ref == (ART_NODE*)n4, "tree unchanged");

    // cleanup
    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: terminator present but leaf mismatch");
    return TRUE;
}

BOOLEAN test_recursive_delete_internal_node48_deep_delete_last_child()
{
    TEST_START("recursive_delete_internal: NODE48 deep delete (edge param) last child");

    reset_mock_state();

    // Kökte NODE48 ve tek çocuk: edge 'x' altında leaf "x"
    ART_NODE* ref = NULL; ART_LEAF* lf = NULL;
    const UCHAR edge = 'x';

    ART_NODE48* n48 = (ART_NODE48*)art_create_node(NODE48);
    TEST_ASSERT(n48, "pre: NODE48");
    n48->base.type = NODE48; n48->base.num_of_child = 0;
    t_zero(n48->child_index, sizeof(n48->child_index));
    t_zero(n48->children, sizeof(n48->children));

    UCHAR kx[1] = { edge };
    lf = make_leaf(kx, 1, 0x55);
    TEST_ASSERT(lf, "leaf");
    n48->children[0] = (ART_NODE*)SET_LEAF(lf);
    n48->child_index[edge] = 1; // map 'x' -> children[0]
    n48->base.num_of_child = 1;
    ref = (ART_NODE*)n48;

    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n48, &ref, kx, 1, 0, 0);
    TEST_ASSERT(out == lf, "returned leaf");
    TEST_ASSERT(ref == NULL, "root freed after last child removal");

    if (out) free_leaf(&out);

    TEST_END("recursive_delete_internal: NODE48 deep delete (edge param) last child");
    return TRUE;
}

BOOLEAN test_recursive_delete_internal_depth_overflow_guard()
{
    TEST_START("recursive_delete_internal: depth overflow guard");

    reset_mock_state();

    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    TEST_ASSERT(n4, "pre");
    n4->base.type = NODE4; n4->base.prefix_length = 2; n4->base.num_of_child = 0;
    n4->base.prefix[0] = 'p'; n4->base.prefix[1] = 'q';

    ART_NODE* ref = (ART_NODE*)n4;
    UCHAR key[3] = { 'p','q','r' }; // içerik önemli değil; overflow’a bakıyoruz

    // depth o kadar büyük ki depth + prefix_length taşsın
    USHORT huge_depth = (USHORT)0xFFFF; // (depth + 2) mod 16-bit < depth → overflow algılanır
    ART_LEAF* out = recursive_delete_internal((ART_NODE*)n4, &ref, key, 3, huge_depth, 0);
    TEST_ASSERT(out == NULL, "overflow -> NULL");

    t_free_tree_best_effort(&ref);

    TEST_END("recursive_delete_internal: depth overflow guard");
    return TRUE;
}


// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_recursive_delete_internal_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting recursive_delete_internal() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_recursive_delete_internal_guards())              all = FALSE; // 1
    if (!test_recursive_delete_internal_leaf_match())          all = FALSE; // 2
    if (!test_recursive_delete_internal_leaf_no_match())       all = FALSE; // 3
    if (!test_recursive_delete_internal_prefix_mismatch())     all = FALSE; // 4
    if (!test_recursive_delete_internal_prefix_match_delete()) all = FALSE; // 5
    if (!test_recursive_delete_internal_missing_child())       all = FALSE; // 6
    if (!test_recursive_delete_internal_delete_root_child())   all = FALSE; // 7
    if (!test_recursive_delete_internal_two_level_delete())    all = FALSE; // 8
    if (!test_recursive_delete_internal_recursion_limit())     all = FALSE; // 9
    if (!test_recursive_delete_internal_terminator_delete())   all = FALSE; // A
    if (!test_recursive_delete_internal_long_prefix_delete())  all = FALSE; // B
    if (!test_recursive_delete_internal_key_shorter_than_prefix())  all = FALSE;
    if (!test_recursive_delete_internal_terminator_mismatch())      all = FALSE;
    if (!test_recursive_delete_internal_node48_deep_delete_last_child()) all = FALSE;
    if (!test_recursive_delete_internal_depth_overflow_guard())     all = FALSE;


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL recursive_delete_internal() TESTS PASSED! \n");
    }
    else {
        LOG_MSG("SOME recursive_delete_internal() TESTS FAILED! \n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif

