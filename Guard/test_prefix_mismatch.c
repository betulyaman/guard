#include "test_art.h"

// Function under test
STATIC USHORT prefix_mismatch(CONST ART_NODE* node, CONST PUCHAR key, USHORT key_length, USHORT depth);

// -------- Small alloc helpers (no CRT) --------
// Utility: fill node->base prefix bytes and length
static VOID t_set_node_prefix(ART_NODE* n, USHORT plen, UCHAR start)
{
    n->prefix_length = plen;
    USHORT copy = (plen > MAX_PREFIX_LENGTH) ? MAX_PREFIX_LENGTH : plen;
    for (USHORT i = 0; i < copy; ++i) n->prefix[i] = (UCHAR)(start + (UCHAR)i);
    // (bytes beyond MAX_PREFIX_LENGTH are implicitly taken from leaf->key in extended path)
}

/* =========================================================
   Test 1: Guard checks
   Covers:
     (1.1) node == NULL  , 0
     (1.2) key  == NULL  , 0
     (1.3) depth > key_length , 0
     (1.4) depth == key_length , 0 (because remaining length is 0)
   Also verify: no alloc/free inside.
   ========================================================= */
BOOLEAN test_prefix_mismatch_guards()
{
    TEST_START("prefix_mismatch: guards");

    reset_mock_state();

    PUCHAR key = t_alloc_key(5, 0x10); // input buffer for non-NULL case
    ART_NODE * hdr = t_alloc_header_only(NODE4); TEST_ASSERT(hdr, "1-pre: header alloc");
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    USHORT r = prefix_mismatch(NULL, key, 5, 0);
    TEST_ASSERT(r == 0, "1.1: NULL node should return 0");

    r = prefix_mismatch(hdr, NULL, 5, 0);
    TEST_ASSERT(r == 0, "1.2: NULL key should return 0");

    r = prefix_mismatch(hdr, key, 5, 6);
    TEST_ASSERT(r == 0, "1.3: depth > key_length should return 0");

    r = prefix_mismatch(hdr, key, 5, 5);
    TEST_ASSERT(r == 0, "1.4: depth == key_length should return 0");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no alloc/free by function");

    t_free(hdr);

    TEST_END("prefix_mismatch: guards");
    return TRUE;
}

/* =========================================================
   Test 2: Basic compare within MAX_PREFIX_LENGTH
   Cases:
     (2.1) full match for node prefix (plen <= MAX_PREFIX_LENGTH) , return plen or remaining (whichever smaller)
     (2.2) mismatch at first byte , return 0
     (2.3) mismatch in the middle , return index
   ========================================================= */
BOOLEAN test_prefix_mismatch_basic_within_max()
{
    TEST_START("prefix_mismatch: basic (<= MAX_PREFIX_LENGTH)");

    // (2.1) full match — expected = min(prefix_length, MAX_PREFIX_LENGTH, remaining)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "2.1-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;

        t_set_node_prefix(&n4->base, 6, 0x20); // intended prefix: 0x20..0x25
        PUCHAR key = t_alloc_key(20, 0x20); TEST_ASSERT(key, "2.1-pre: key alloc");

        const USHORT depth = 0;
        const USHORT remaining = (USHORT)(20 - depth);
        const USHORT pfx_cap = (USHORT)((n4->base.prefix_length < (USHORT)MAX_PREFIX_LENGTH)
            ? n4->base.prefix_length : (USHORT)MAX_PREFIX_LENGTH);
        const USHORT expected = (pfx_cap < remaining) ? pfx_cap : remaining;

        USHORT r = prefix_mismatch(&n4->base, key, 20, depth);
        TEST_ASSERT(r == expected, "2.1: full match should return min(prefix, MAX_PREFIX_LENGTH, remaining)");

        t_free(key); t_free(n4);
    }

    // (2.2) mismatch at first byte (depth=0)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "2.2-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;

        t_set_node_prefix(&n4->base, 4, 0x30);             // 0x30,31,32,33
        PUCHAR key = t_alloc_key(10, 0x40); TEST_ASSERT(key, "2.2-pre: key alloc"); // starts 0x40 -> mismatch at index 0

        USHORT r = prefix_mismatch(&n4->base, key, 10, 0);
        TEST_ASSERT(r == 0, "2.2: first byte mismatch should return 0");

        t_free(key); t_free(n4);
    }

    // (2.3) mismatch in the middle (depth=0)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "2.3-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;

        t_set_node_prefix(&n4->base, 5, 0x50);            // 0x50,51,52,53,54
        PUCHAR key = t_alloc_key(10, 0x50); TEST_ASSERT(key, "2.3-pre: key alloc");
        key[2] = 0x7F; // mismatch at index 2

        USHORT r = prefix_mismatch(&n4->base, key, 10, 0);
        TEST_ASSERT(r == 2, "2.3: mismatch at index 2 should return 2");

        t_free(key); t_free(n4);
    }

    TEST_END("prefix_mismatch: basic (<= MAX_PREFIX_LENGTH)");
    return TRUE;
}

/* =========================================================
   Test 3: Limited by remaining key length
   Case:
     - node->prefix_length is larger than remaining (key_length - depth)
     - All compared bytes match , return remaining length
   ========================================================= */
BOOLEAN test_prefix_mismatch_limited_by_remaining()
{
    TEST_START("prefix_mismatch: limited by remaining key");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "3-pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 0;

    // node->prefix_length remaining'den büyük olsun ki 'remaining' limitlesin
    t_set_node_prefix(&n4->base, 10, 0x10);

    const USHORT key_len = 6;
    PUCHAR key = t_alloc_key(key_len, 0x00); TEST_ASSERT(key, "3-pre: key alloc");

    const USHORT depth = 2;
    const USHORT remaining = (USHORT)(key_len - depth); // 4

    // Beklenen karşılaştırma penceresi
    const USHORT pfx_cap = (USHORT)((n4->base.prefix_length < (USHORT)MAX_PREFIX_LENGTH)
        ? n4->base.prefix_length : (USHORT)MAX_PREFIX_LENGTH);
    const USHORT cmp_len = (pfx_cap < remaining) ? pfx_cap : remaining;

    // Anahtarın depth bölgesini düğüm prefix'i ile birebir eşleştir
    // Böylece 'cmp_len' kadar tam eşleşme garanti.
    for (USHORT i = 0; i < cmp_len; ++i) {
        key[depth + i] = n4->base.prefix[i];
    }

    USHORT r = prefix_mismatch(&n4->base, key, key_len, depth);
    TEST_ASSERT(r == cmp_len, "3.1: must return min(prefix, MAX_PREFIX_LENGTH, remaining)");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: limited by remaining key");
    return TRUE;
}

/* =========================================================
   Test 4: Extended compare path (node->prefix_length > MAX_PREFIX_LENGTH)
   Sub-cases:
     (4.1) minimum(node)==NULL , return index accumulated so far (no crash)
     (4.2) depth > leaf->key_length , return index so far
     (4.3) extended compare matches extra bytes then mismatches
     (4.4) extended compare full match to its limit
   Notes:
     - We use NODE4 with one child leaf to make minimum(node) find that leaf.
     - Node.prefix[0..MAX_PREFIX_LENGTH-1] matches key; extra bytes come from leaf->key.
   ========================================================= */
BOOLEAN test_prefix_mismatch_extended_path()
{
    TEST_START("prefix_mismatch: extended compare path");

    // (4.1) minimum(node) == NULL  (num_of_child=0 and no leaf)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.1-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;

        // Force extended path need:
        t_set_node_prefix(&n4->base, (USHORT)(MAX_PREFIX_LENGTH + 5), 0x20);

        PUCHAR key = t_alloc_key((USHORT)(MAX_PREFIX_LENGTH + 10), 0x20); TEST_ASSERT(key, "4.1-pre: key alloc");

        // First MAX_PREFIX_LENGTH bytes equal; since no children, minimum() returns NULL.
        USHORT r = prefix_mismatch(&n4->base, key, (USHORT)(MAX_PREFIX_LENGTH + 10), 0);
        TEST_ASSERT(r == MAX_PREFIX_LENGTH, "4.1: with no leaf, should return index accumulated so far");

        t_free(key); t_free(n4);
    }

    // (4.2) depth > leaf->key_length , should return index accumulated so far
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.2-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 1;

        t_set_node_prefix(&n4->base, (USHORT)(MAX_PREFIX_LENGTH + 3), 0x30);

        ART_LEAF* lf = test_alloc_leaf(8, 0x30); TEST_ASSERT(lf, "4.2-pre: leaf alloc");
        n4->children[0] = SET_LEAF(lf);

        const USHORT key_len = 20;
        PUCHAR key = t_alloc_key(key_len, 0x00); TEST_ASSERT(key, "4.2-pre: key alloc");

        const USHORT depth = 10; // leaf->key_length = 8 ⇒ depth is past leaf length
        const USHORT remaining = (USHORT)(key_len - depth);
        const USHORT pfx_cap = (USHORT)((n4->base.prefix_length < (USHORT)MAX_PREFIX_LENGTH)
            ? n4->base.prefix_length : (USHORT)MAX_PREFIX_LENGTH);
        const USHORT expected_base = (pfx_cap < remaining) ? pfx_cap : remaining;

        // *** Important: make sure the comparison window matches the node prefix ***
        // Without this, the default test key pattern won't match the node prefix
        // and will cause early mismatch unrelated to the intended scenario.
        for (USHORT i = 0; i < expected_base; ++i) {
            key[depth + i] = n4->base.prefix[i];
        }

        USHORT r = prefix_mismatch(&n4->base, key, key_len, depth);
        TEST_ASSERT(r == expected_base, "4.2: depth past leaf => return index accumulated so far");

        t_free(key); t_free(lf); t_free(n4);
    }

    // (4.3) extended compare: match extra bytes then mismatch
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.3-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 1;

        // Need extended: prefix_length beyond MAX_PREFIX_LENGTH
        USHORT total_plen = (USHORT)(MAX_PREFIX_LENGTH + 6);
        t_set_node_prefix(&n4->base, total_plen, 0x40);

        // Leaf holds the continuation bytes (starting at same pattern)
        ART_LEAF* lf = test_alloc_leaf((USHORT)(MAX_PREFIX_LENGTH + 8), 0x40); TEST_ASSERT(lf, "4.3-pre: leaf alloc");
        n4->children[0] = SET_LEAF(lf);

        // Key same as leaf, but make a mismatch 3 bytes after MAX_PREFIX_LENGTH
        USHORT klen = (USHORT)(MAX_PREFIX_LENGTH + 10);
        PUCHAR key = t_alloc_key(klen, 0x40); TEST_ASSERT(key, "4.3-pre: key alloc");
        key[MAX_PREFIX_LENGTH + 3] = 0xEE; // mismatch here

        USHORT r = prefix_mismatch(&n4->base, key, klen, 0);
        TEST_ASSERT(r == MAX_PREFIX_LENGTH + 3, "4.3: should return first mismatch index in extended area");

        t_free(key); t_free(lf); t_free(n4);
    }

    // (4.4) extended compare: full match up to min(leaf remainder, remaining_key_length, node->prefix_length)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.4-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 1;

        // node prefix asks for more than MAX_PREFIX_LENGTH (e.g., +8)
        USHORT node_plen = (USHORT)(MAX_PREFIX_LENGTH + 8);
        t_set_node_prefix(&n4->base, node_plen, 0x55);

        // Leaf sufficiently long so extended compare can happen
        ART_LEAF* lf = test_alloc_leaf((USHORT)(MAX_PREFIX_LENGTH + 20), 0x55); 
        TEST_ASSERT(lf, "4.4-pre: leaf alloc");
        // Set up the key-child mapping properly for NODE4
        n4->keys[0] = 0x01;  // Set key for the child
        n4->children[0] = SET_LEAF(lf);

        // Key length limits the comparison (remaining_key_length from depth=2)
        USHORT depth = 2;
        USHORT key_len = (USHORT)(MAX_PREFIX_LENGTH + 6 + depth); // forces stop before node_plen
        PUCHAR key = t_alloc_key(key_len, 0x55); TEST_ASSERT(key, "4.4-pre: key alloc");

        // Expected return = min( min(leaf->key_length - depth, remaining_key_length), node->prefix_length )
        USHORT remaining_key_length = key_len - depth;
        USHORT max_compare_length = remaining_key_length;                                   // leaf is long enough
        if (max_compare_length > node_plen) max_compare_length = node_plen;                 // cap by node->prefix_length

        USHORT r = prefix_mismatch(&n4->base, key, key_len, depth);
        LOG_MSG("\n4.4: full match should return computed max compare length RETURNED : % d - MAX : % d\n", r, max_compare_length);
        TEST_ASSERT(r == max_compare_length, "4.4: full match should return computed max compare length");

        t_free(key); t_free(lf); t_free(n4);
    }

    TEST_END("prefix_mismatch: extended compare path");
    return TRUE;
}

/* =========================================================
   Test 5: Depth offset within first block
   Case:
     - depth > 0; ensure comparison starts at key[depth]
     - mismatch detected relative to that offset
   ========================================================= */
BOOLEAN test_prefix_mismatch_with_depth_offset()
{
    TEST_START("prefix_mismatch: depth offset");

    // 5.1: mismatch after depth should return relative index 1 (or cmp_len if window < 2)
    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "5-pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 0;

    t_set_node_prefix(&n4->base, 5, 0x10); // prefix bytes: 0x10, 0x11, 0x12, 0x13, 0x14
    PUCHAR key = t_alloc_key(10, 0x00); TEST_ASSERT(key, "5-pre: key alloc");

    const USHORT depth = 2;
    const USHORT remaining = (USHORT)(10 - depth);
    const USHORT pfx_cap = (USHORT)((n4->base.prefix_length < (USHORT)MAX_PREFIX_LENGTH)
        ? n4->base.prefix_length : (USHORT)MAX_PREFIX_LENGTH);
    const USHORT cmp_len = (pfx_cap < remaining) ? pfx_cap : remaining;

    // *** Step 1: Align key bytes with node prefix in the compare window ***
    // This ensures the first bytes match, so we can precisely control where the mismatch occurs.
    for (USHORT i = 0; i < cmp_len; ++i) {
        key[depth + i] = n4->base.prefix[i];
    }

    // *** Step 2: Inject a mismatch at relative index 1 (if enough compare length) ***
    // This forces prefix_mismatch() to detect the mismatch at the correct position.
    if (cmp_len >= 2) {
        key[depth + 1] ^= 0x7F; // change the byte to something different
    }

    USHORT r = prefix_mismatch(&n4->base, key, 10, depth);
    const USHORT expected = (cmp_len >= 2) ? 1 : cmp_len;
    TEST_ASSERT(r == expected, "5.1: mismatch after depth should return relative index 1 (or cmp_len if window < 2)");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: depth offset");
    return TRUE;
}

/* =========================================================
   Test 6: No alloc/free side-effects
   Purpose:
     - Verify function itself does not allocate/free memory
       (it only reads; minimum() also only reads pointers).
   ========================================================= */
BOOLEAN test_prefix_mismatch_no_allocfree_sideeffects()
{
    TEST_START("prefix_mismatch: no alloc/free side-effects");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "6-pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 0;
    t_set_node_prefix(&n4->base, 4, 0x22);

    PUCHAR key = t_alloc_key(8, 0x22); TEST_ASSERT(key, "6-pre: key alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    (void)prefix_mismatch(&n4->base, key, 8, 0);
    (void)prefix_mismatch(&n4->base, key, 8, 1);
    (void)prefix_mismatch(&n4->base, key, 8, 2);

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "6.1: counters unchanged across calls");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: no alloc/free side-effects");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_prefix_mismatch_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting prefix_mismatch() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_prefix_mismatch_guards())                 all_passed = FALSE; // 1
    if (!test_prefix_mismatch_basic_within_max())       all_passed = FALSE; // 2
    if (!test_prefix_mismatch_limited_by_remaining())   all_passed = FALSE; // 3
    if (!test_prefix_mismatch_extended_path())          all_passed = FALSE; // 4
    if (!test_prefix_mismatch_with_depth_offset())      all_passed = FALSE; // 5
    if (!test_prefix_mismatch_no_allocfree_sideeffects()) all_passed = FALSE; // 6

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL prefix_mismatch() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME prefix_mismatch() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
