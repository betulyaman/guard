#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC USHORT prefix_mismatch(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth, _In_opt_ CONST ART_LEAF* rep_leaf);

// -------- Small alloc helpers (no CRT) --------
// Utility: fill node->base prefix bytes and length
static VOID t_set_node_prefix(ART_NODE* n, USHORT plen, UCHAR start)
{
    n->prefix_length = plen;
    USHORT copy = (plen > MAX_PREFIX_LENGTH) ? MAX_PREFIX_LENGTH : plen;
    for (USHORT i = 0; i < copy; ++i) n->prefix[i] = (UCHAR)(start + (UCHAR)i);
    // (bytes beyond MAX_PREFIX_LENGTH are implicitly taken from leaf->key in extended path)
}

/*
   Test 1: Guard checks
   Covers:
     (1.1) node == NULL  , 0
     (1.2) key  == NULL  , 0
     (1.3) depth > key_length , 0
     (1.4) depth == key_length , 0 (because remaining length is 0)
   Also verify: no alloc/free inside.
*/
BOOLEAN test_prefix_mismatch_guards()
{
    TEST_START("prefix_mismatch: guards");

    reset_mock_state();

    PUCHAR key = t_alloc_key(5, 0x10); // input buffer for non-NULL case
    ART_NODE* hdr = t_alloc_header_only(NODE4); TEST_ASSERT(hdr, "1-pre: header alloc");
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable:6387)
    USHORT r = prefix_mismatch(NULL, key, 5, 0, NULL);
#pragma warning(pop)
    TEST_ASSERT(r == 0, "1.1: NULL node should return 0");
#pragma warning(push)
#pragma warning(disable:6387)
    r = prefix_mismatch(hdr, NULL, 5, 0, NULL);
#pragma warning(pop)
    TEST_ASSERT(r == 0, "1.2: NULL key should return 0");

    r = prefix_mismatch(hdr, key, 5, 6, NULL);
    TEST_ASSERT(r == 0, "1.3: depth > key_length should return 0");

    r = prefix_mismatch(hdr, key, 5, 5, NULL);
    TEST_ASSERT(r == 0, "1.4: depth == key_length should return 0");

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.x: no alloc/free by function");

    t_free(hdr);
    t_free(key);

    TEST_END("prefix_mismatch: guards");
    return TRUE;
}

/*
   Test 2: Basic compare within MAX_PREFIX_LENGTH
   Cases:
     (2.1) full match for node prefix (plen <= MAX_PREFIX_LENGTH) , return plen or remaining (whichever smaller)
     (2.2) mismatch at first byte , return 0
     (2.3) mismatch in the middle , return index
*/
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

        USHORT r = prefix_mismatch(&n4->base, key, 20, depth, NULL);
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

        USHORT r = prefix_mismatch(&n4->base, key, 10, 0, NULL);
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

        USHORT r = prefix_mismatch(&n4->base, key, 10, 0, NULL);
        TEST_ASSERT(r == 2, "2.3: mismatch at index 2 should return 2");

        t_free(key); t_free(n4);
    }

    TEST_END("prefix_mismatch: basic (<= MAX_PREFIX_LENGTH)");
    return TRUE;
}

/*
   Test 3: Limited by remaining key length
   Case:
     - node->prefix_length is larger than remaining (key_length - depth)
     - All compared bytes match , return remaining length
*/
BOOLEAN test_prefix_mismatch_limited_by_remaining()
{
    TEST_START("prefix_mismatch: limited by remaining key");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "3-pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 0;

    // Make node->prefix_length larger than remaining to ensure 'remaining' is the limit
    t_set_node_prefix(&n4->base, 10, 0x10);

    const USHORT key_len = 6;
    PUCHAR key = t_alloc_key(key_len, 0x00); TEST_ASSERT(key, "3-pre: key alloc");

    const USHORT depth = 2;
    const USHORT remaining = (USHORT)(key_len - depth); // 4

    // Expected comparison window
    const USHORT pfx_cap = (USHORT)((n4->base.prefix_length < (USHORT)MAX_PREFIX_LENGTH)
        ? n4->base.prefix_length : (USHORT)MAX_PREFIX_LENGTH);
    const USHORT cmp_len = (pfx_cap < remaining) ? pfx_cap : remaining;

    // Align key's compare window to match the node prefix exactly
    for (USHORT i = 0; i < cmp_len; ++i) {
        key[depth + i] = n4->base.prefix[i];
    }

    USHORT r = prefix_mismatch(&n4->base, key, key_len, depth, NULL);
    TEST_ASSERT(r == cmp_len, "3.1: must return min(prefix, MAX_PREFIX_LENGTH, remaining)");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: limited by remaining key");
    return TRUE;
}

/*
   Test 4: Extended compare path (node->prefix_length > MAX_PREFIX_LENGTH)
   Sub-cases:
     (4.1) minimum(node)==NULL , return index accumulated so far (no crash)
     (4.2) depth > leaf->key_length , return index so far
     (4.3) extended compare matches extra bytes then mismatches
     (4.4) extended compare full match to its limit
   Notes:
     - We use NODE4 with one child leaf to make minimum(node) find that leaf.
     - Node.prefix[0..MAX_PREFIX_LENGTH-1] matches key; extra bytes come from leaf->key.
*/
BOOLEAN test_prefix_mismatch_extended_path()
{
    TEST_START("prefix_mismatch: extended compare path");

    // (4.1) minimum(node) == NULL  (num_of_child=0 and no leaf)
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.1-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;

        // Force extended path requirement
        t_set_node_prefix(&n4->base, (USHORT)(MAX_PREFIX_LENGTH + 5), 0x20);

        PUCHAR key = t_alloc_key((USHORT)(MAX_PREFIX_LENGTH + 10), 0x20); TEST_ASSERT(key, "4.1-pre: key alloc");

        USHORT r = prefix_mismatch(&n4->base, key, (USHORT)(MAX_PREFIX_LENGTH + 10), 0, NULL);
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

        // Ensure header window matches so we specifically test the "depth past leaf" case
        for (USHORT i = 0; i < expected_base; ++i) {
            key[depth + i] = n4->base.prefix[i];
        }

        USHORT r = prefix_mismatch(&n4->base, key, key_len, depth, NULL);
        TEST_ASSERT(r == expected_base, "4.2: depth past leaf => return index accumulated so far");

        t_free(key); t_free(lf); t_free(n4);
    }

    // (4.3) extended compare: match extra bytes then mismatch
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "4.3-pre: node alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 1;

        // Require extended compare (prefix_length beyond MAX_PREFIX_LENGTH)
        USHORT total_plen = (USHORT)(MAX_PREFIX_LENGTH + 6);
        t_set_node_prefix(&n4->base, total_plen, 0x40);

        // Leaf holds the continuation bytes (same pattern)
        ART_LEAF* lf = test_alloc_leaf((USHORT)(MAX_PREFIX_LENGTH + 8), 0x40); TEST_ASSERT(lf, "4.3-pre: leaf alloc");
        n4->children[0] = SET_LEAF(lf);

        // Key = leaf, but with a deliberate mismatch 3 bytes after MAX_PREFIX_LENGTH
        USHORT klen = (USHORT)(MAX_PREFIX_LENGTH + 10);
        PUCHAR key = t_alloc_key(klen, 0x40); TEST_ASSERT(key, "4.3-pre: key alloc");
        key[MAX_PREFIX_LENGTH + 3] = 0xEE; // mismatch here

        USHORT r = prefix_mismatch(&n4->base, key, klen, 0, NULL);
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
        // Ensure child linkage is valid (not strictly required for minimum() in most impls, but safe)
        n4->children[0] = SET_LEAF(lf);

        // Limit comparison by remaining key length from depth=2
        USHORT depth = 2;
        USHORT key_len = (USHORT)(MAX_PREFIX_LENGTH + 6 + depth); // forces stop before node_plen
        PUCHAR key = t_alloc_key(key_len, 0x55); TEST_ASSERT(key, "4.4-pre: key alloc");

        // Expected return = min(remaining_key_length, node->prefix_length, leaf->key_length - depth)
        USHORT remaining_key_length = (USHORT)(key_len - depth);
        USHORT max_compare_length = remaining_key_length;
        if (max_compare_length > node_plen) max_compare_length = node_plen;
        if (max_compare_length > (USHORT)(lf->key_length - depth)) max_compare_length = (USHORT)(lf->key_length - depth);

        USHORT r = prefix_mismatch(&n4->base, key, key_len, depth, NULL);
        LOG_MSG("\n4.4: full match should return computed max compare length RETURNED : %u - MAX : %u\n", r, max_compare_length);
        TEST_ASSERT(r == max_compare_length, "4.4: full match should return computed max compare length");

        t_free(key); t_free(lf); t_free(n4);
    }

    TEST_END("prefix_mismatch: extended compare path");
    return TRUE;
}

/*
   Test 5: Depth offset within first block
   Case:
     - depth > 0; ensure comparison starts at key[depth]
     - mismatch detected relative to that offset
*/
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

    // Align key bytes with node prefix in the compare window
    for (USHORT i = 0; i < cmp_len; ++i) {
        key[depth + i] = n4->base.prefix[i];
    }

    // Inject a mismatch at relative index 1 (if enough window)
    if (cmp_len >= 2) {
        key[depth + 1] ^= 0x7F; // force difference
    }

    USHORT r = prefix_mismatch(&n4->base, key, 10, depth, NULL);
    const USHORT expected = (cmp_len >= 2) ? 1 : cmp_len;
    TEST_ASSERT(r == expected, "5.1: mismatch after depth should return relative index 1 (or cmp_len if window < 2)");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: depth offset");
    return TRUE;
}

/*
   Test 6: No alloc/free side-effects
   Purpose:
     - Verify function itself does not allocate/free memory
       (it only reads; minimum() also only reads pointers).
*/
BOOLEAN test_prefix_mismatch_no_allocfree_sideeffects()
{
    TEST_START("prefix_mismatch: no alloc/free side-effects");

    reset_mock_state();

    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "6-pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 0;
    t_set_node_prefix(&n4->base, 4, 0x22);

    PUCHAR key = t_alloc_key(8, 0x22); TEST_ASSERT(key, "6-pre: key alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    (void)prefix_mismatch(&n4->base, key, 8, 0, NULL);
    (void)prefix_mismatch(&n4->base, key, 8, 1, NULL);
    (void)prefix_mismatch(&n4->base, key, 8, 2, NULL);

    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "6.1: counters unchanged across calls");

    t_free(key); t_free(n4);

    TEST_END("prefix_mismatch: no alloc/free side-effects");
    return TRUE;
}

BOOLEAN test_prefix_mismatch_drift_tolerated_by_leaf()
{
    TEST_START("prefix_mismatch: drift tolerated by leaf");

    reset_mock_state();
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 1;

    // Stored header prefix: 0x40,41,42,43
    t_set_node_prefix(&n4->base, 4, 0x40);

    // Leaf and key follow the same pattern: 0x40,41,42,43,...
    ART_LEAF* lf = test_alloc_leaf(8, 0x40); TEST_ASSERT(lf, "pre: leaf alloc");
    n4->children[0] = SET_LEAF(lf);

    // Introduce header drift at i=2 (header says 0x99) while leaf+key still say 0x42.
    n4->base.prefix[2] = 0x99; // drift

    PUCHAR key = t_alloc_key(8, 0x40); TEST_ASSERT(key, "pre: key alloc");

    USHORT r = prefix_mismatch(&n4->base, key, 8, 0, NULL);
    // With drift tolerance verified by leaf agreement, should match the full stored window (4).
    TEST_ASSERT(r == 4, "drift validated by leaf must allow full window match");

    t_free(key); t_free(n4); t_free(lf);
    TEST_END("prefix_mismatch: drift tolerated by leaf");
    return TRUE;
}

BOOLEAN test_prefix_mismatch_rep_leaf_too_short_falls_back()
{
    TEST_START("prefix_mismatch: rep_leaf too short -> fallback to minimum");

    reset_mock_state();
    ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4, "pre: node alloc");
    n4->base.type = NODE4; n4->base.num_of_child = 1;

    // Long logical prefix (extended path)
    t_set_node_prefix(&n4->base, (USHORT)(MAX_PREFIX_LENGTH + 4), 0x50);

    // Attach a long leaf to be discoverable by minimum(node)
    ART_LEAF* lf_long = test_alloc_leaf((USHORT)(MAX_PREFIX_LENGTH + 10), 0x50);
    TEST_ASSERT(lf_long, "pre: long leaf");
    n4->children[0] = SET_LEAF(lf_long);

    // Provide a representative leaf that is too short for the requested depth
    ART_LEAF* rep_short = test_alloc_leaf(4, 0x50); TEST_ASSERT(rep_short, "pre: short rep");

    // Key compatible with lf_long
    PUCHAR key = t_alloc_key((USHORT)(MAX_PREFIX_LENGTH + 12), 0x50); TEST_ASSERT(key, "pre: key");

    // Depth beyond rep_short->key_length; forces fallback to minimum(node)
    USHORT depth = 6;

    USHORT r = prefix_mismatch(&n4->base, key, (USHORT)(MAX_PREFIX_LENGTH + 12), depth, rep_short);

    // Expected: first_window + as much of the extended area as can be validated
    USHORT remaining = (USHORT)(MAX_PREFIX_LENGTH + 12 - depth);
    USHORT first_window = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, (USHORT)min(n4->base.prefix_length, remaining));
    USHORT logical_extra = (USHORT)(n4->base.prefix_length > first_window ? n4->base.prefix_length - first_window : 0);
    USHORT to_check = (USHORT)min(logical_extra, (USHORT)(remaining - first_window));

    TEST_ASSERT(r == (USHORT)(first_window + to_check), "rep_leaf too short must fallback to minimum() for extended check");

    t_free(key); t_free(rep_short); t_free(n4); t_free(lf_long);
    TEST_END("prefix_mismatch: rep_leaf too short -> fallback to minimum");
    return TRUE;
}

/*
   Suite Runner
*/
NTSTATUS run_all_prefix_mismatch_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting prefix_mismatch() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_prefix_mismatch_guards())                     all_passed = FALSE; // 1
    if (!test_prefix_mismatch_basic_within_max())           all_passed = FALSE; // 2
    if (!test_prefix_mismatch_limited_by_remaining())       all_passed = FALSE; // 3
    if (!test_prefix_mismatch_extended_path())              all_passed = FALSE; // 4
    if (!test_prefix_mismatch_with_depth_offset())          all_passed = FALSE; // 5
    if (!test_prefix_mismatch_no_allocfree_sideeffects())   all_passed = FALSE; // 6
    if (!test_prefix_mismatch_drift_tolerated_by_leaf())    all_passed = FALSE; // 7
    if (!test_prefix_mismatch_rep_leaf_too_short_falls_back()) all_passed = FALSE; // 8

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

#endif
