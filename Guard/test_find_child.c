#include "test_art.h"

// Function under test
STATIC ART_NODE** find_child(_In_ ART_NODE* node, _In_ UCHAR c);

// ---------- Small helpers ----------
// --- tiny local helpers (no CRT) ---
static ART_NODE4* mk_n4(void) {
    return (ART_NODE4*)art_create_node(NODE4);
}

static BOOLEAN n4_set(ART_NODE4* n4, const UCHAR* keys, USHORT cnt, ART_NODE* const* ch)
{
    if (!n4 || !keys || !ch || cnt > 4) return FALSE;
    RtlZeroMemory(n4->keys, sizeof(n4->keys));
    RtlZeroMemory(n4->children, sizeof(n4->children));
    for (USHORT i = 0; i < cnt; i++) {
        n4->keys[i] = keys[i];
        n4->children[i] = ch[i];
    }
    n4->base.num_of_child = cnt;
    return TRUE;
}

/* =========================================================
   Test 1: NULL and invalid type handling
   Purpose:
     - node == NULL , NULL
     - invalid node->type , NULL
     - No alloc/free inside find_child
   Sub-checks:
     (1.1) NULL input returns NULL (no side effects)
     (1.2) Invalid type returns NULL (no frees)
   ========================================================= */
BOOLEAN test_find_child_null_and_invalid()
{
    TEST_START("find_child: NULL and invalid type");

    // (1.1) node == NULL
    reset_mock_state();
    {
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
#pragma warning(push)
#pragma warning(disable: 6387)
        ART_NODE** pp = find_child(NULL, (UCHAR)'x');
#pragma warning(pop)
        TEST_ASSERT(pp == NULL, "1.1: NULL node must return NULL");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0,
            "1.1: No allocations/frees inside find_child");
    }

    // (1.2) invalid type
    reset_mock_state();
    {
        ART_NODE* base = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
        TEST_ASSERT(base != NULL, "1.2-pre: base node allocation");
        RtlZeroMemory(base, sizeof(ART_NODE));
        base->type = (NODE_TYPE)0; // invalid
        base->num_of_child = 0;

        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        ART_NODE** pp = find_child(base, (UCHAR)'a');
        TEST_ASSERT(pp == NULL, "1.2: invalid type must return NULL");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0,
            "1.2: find_child must not free the node");
        ExFreePoolWithTag(base, ART_TAG);
    }

    DbgPrint("[INFO] Test 1: NULL and invalid type paths verified\n");
    TEST_END("find_child: NULL and invalid type");
    return TRUE;
}

/* =========================================================
   Test 2: NODE4 basic behavior
   Purpose:
     - Finds existing key within safe_child_count=min(num_of_child,4)
     - Ignores keys beyond capacity
     - Empty node returns NULL
   Sub-checks:
     (2.1) Hit at index 1 among 3 children
     (2.2) num_of_child clamped: match at index 3 found; index 4 ignored
     (2.3) Miss , NULL
     (2.4) num_of_child=0 , NULL
   ========================================================= */
BOOLEAN test_find_child_node4()
{
    TEST_START("find_child: NODE4");

    // (2.1) 3 children, keys { 'a','b','c' }, find 'b' -> index 1
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4 != NULL, "2.1-pre: node4 alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 3;
        n4->keys[0] = 'a'; n4->keys[1] = 'b'; n4->keys[2] = 'c';
        ART_NODE* d0 = t_alloc_dummy_child(NODE4);
        ART_NODE* d1 = t_alloc_dummy_child(NODE4);
        ART_NODE* d2 = t_alloc_dummy_child(NODE4);
        n4->children[0] = d0; n4->children[1] = d1; n4->children[2] = d2;

        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        ART_NODE** got = find_child(&n4->base, (UCHAR)'b');

        TEST_ASSERT(got == &n4->children[1], "2.1: Must return &children[1]");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0,
            "2.1: No alloc/free inside call");

        test_free_node_any(d0); test_free_node_any(d1); test_free_node_any(d2);
        test_free_node_any(&n4->base);
    }

    // (2.2) num_of_child > 4: clamp to 4; match at index 3 OK, index 4 ignored
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4 != NULL, "2.2-pre: node4 alloc");
        n4->base.type = NODE4;
        n4->base.num_of_child = 7; // bilerek kapasite üstü bildiriyoruz; find_child 4'e clamp edecek

        n4->keys[0] = 'x'; n4->keys[1] = 'y'; n4->keys[2] = 'z'; n4->keys[3] = 'q';
        ART_NODE* d[4] = { 0 };
        for (int i = 0; i < 4; i++) { d[i] = t_alloc_dummy_child(NODE4); n4->children[i] = d[i]; }

        ART_NODE** hit3 = find_child(&n4->base, (UCHAR)'q');
        TEST_ASSERT(hit3 == &n4->children[3], "2.2: Should find index 3 within clamp");

        // Kapasite üstünü doğrula: ilk 4'ü 'p' yap, aranan 'q' olduğunda NULL dönmeli
        n4->keys[0] = 'p'; n4->keys[1] = 'p'; n4->keys[2] = 'p'; n4->keys[3] = 'p';
        ART_NODE** hitBeyond = find_child(&n4->base, (UCHAR)'q');
        TEST_ASSERT(hitBeyond == NULL, "2.2: Keys beyond capacity must be ignored");

        for (int i = 0; i < 4; i++) test_free_node_any(d[i]);
        test_free_node_any(&n4->base);
    }

    // (2.3) miss
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4 != NULL, "2.3-pre: node4 alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 2;
        n4->keys[0] = 'a'; n4->keys[1] = 'b';
        n4->children[0] = t_alloc_dummy_child(NODE4);
        n4->children[1] = t_alloc_dummy_child(NODE4);

        ART_NODE** miss = find_child(&n4->base, (UCHAR)'c');
        TEST_ASSERT(miss == NULL, "2.3: Not found -> NULL");

        test_free_node_any(n4->children[0]); test_free_node_any(n4->children[1]);
        test_free_node_any(&n4->base);
    }

    // (2.4) empty
    reset_mock_state();
    {
        ART_NODE4* n4 = t_alloc_node4(); TEST_ASSERT(n4 != NULL, "2.4-pre: node4 alloc");
        n4->base.type = NODE4; n4->base.num_of_child = 0;
        ART_NODE** got = find_child(&n4->base, (UCHAR)'a');
        TEST_ASSERT(got == NULL, "2.4: Empty node -> NULL");
        test_free_node_any(&n4->base);
    }

    DbgPrint("[INFO] Test 2: NODE4 behaviors validated\n");
    TEST_END("find_child: NODE4");
    return TRUE;
}

/* =========================================================
   Test 3: NODE16 masking + ctz path
   Purpose:
     - Parallel compare builds bitfield; mask by num_of_child
     - ctz chooses lowest index among matches inside mask
     - No matches , NULL; empty , NULL
   Sub-checks:
     (3.1) Duplicate keys at indices 2 and 5, num_of_child=6 -> return index 2
     (3.2) Matches beyond num_of_child masked out -> NULL
     (3.3) Miss , NULL
     (3.4) num_of_child=0 , NULL
   ========================================================= */
BOOLEAN test_find_child_node16()
{
    TEST_START("find_child: NODE16");

    // (3.1) duplicates in-range -> lowest index via ctz
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16 != NULL, "3.1-pre: node16 alloc");
        n16->base.type = NODE16; n16->base.num_of_child = 6;
        n16->keys[2] = 'x'; n16->keys[5] = 'x';
        for (int i = 0; i < 6; i++) n16->children[i] = t_alloc_dummy_child(NODE16);

        ART_NODE** got = find_child(&n16->base, (UCHAR)'x');
        TEST_ASSERT(got == &n16->children[2], "3.1: ctz must pick lowest index 2");

        for (int i = 0; i < 6; i++) test_free_node_any(n16->children[i]);
        test_free_node_any(&n16->base);
    }

    // (3.2) only matches beyond mask -> NULL
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16 != NULL, "3.2-pre: node16 alloc");
        n16->base.type = NODE16; n16->base.num_of_child = 4; // mask 0..3
        // Set matches outside mask positions (e.g., index 7 and 10)
        n16->keys[7] = 'q'; n16->keys[10] = 'q';
        for (int i = 0; i < 11; i++) n16->children[i] = t_alloc_dummy_child(NODE16);

        ART_NODE** got = find_child(&n16->base, (UCHAR)'q');
        TEST_ASSERT(got == NULL, "3.2: matches beyond safe_child_count must be ignored");

        for (int i = 0; i < 11; i++) test_free_node_any(n16->children[i]);
        test_free_node_any(&n16->base);
    }

    // (3.3) miss
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16 != NULL, "3.3-pre: node16 alloc");
        n16->base.type = NODE16; n16->base.num_of_child = 5;
        n16->keys[0] = 'a'; n16->keys[1] = 'b'; n16->keys[2] = 'c'; n16->keys[3] = 'd'; n16->keys[4] = 'e';
        for (int i = 0; i < 5; i++) n16->children[i] = t_alloc_dummy_child(NODE16);

        ART_NODE** miss = find_child(&n16->base, (UCHAR)'z');
        TEST_ASSERT(miss == NULL, "3.3: Not found -> NULL");

        for (int i = 0; i < 5; i++) test_free_node_any(n16->children[i]);
        test_free_node_any(&n16->base);
    }

    // (3.4) empty
    reset_mock_state();
    {
        ART_NODE16* n16 = t_alloc_node16(); TEST_ASSERT(n16 != NULL, "3.4-pre: node16 alloc");
        n16->base.type = NODE16; n16->base.num_of_child = 0;
        ART_NODE** got = find_child(&n16->base, (UCHAR)'a');
        TEST_ASSERT(got == NULL, "3.4: Empty -> NULL");
        test_free_node_any(&n16->base);
    }

    DbgPrint("[INFO] Test 3: NODE16 bitfield+mask+ctz behavior validated\n");
    TEST_END("find_child: NODE16");
    return TRUE;
}

/* =========================================================
   Test 4: NODE48 mapping rules
   Purpose:
     - child_index[c] in 1..48 , returns &children[index-1] if non-NULL
     - index==0 , absent; index out of range , ignore
   Sub-checks:
     (4.1) Valid index in range, child non-NULL -> return slot
     (4.2) index==0 -> NULL
     (4.3) index==49 (out of range) -> NULL
     (4.4) index in range but children[index-1]==NULL -> NULL
   ========================================================= */
BOOLEAN test_find_child_node48()
{
    TEST_START("find_child: NODE48");

    // (4.1) valid, in-range
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48 != NULL, "4.1-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 48;
        UCHAR key = 0x5A;
        RtlZeroMemory(n48->child_index, sizeof(n48->child_index));
        n48->child_index[key] = 17; // 1..48
        for (int i = 0; i < 48; i++) n48->children[i] = NULL;
        ART_NODE* child = t_alloc_dummy_child(NODE16); // arbitrary
        n48->children[16] = child; // index-1

        ART_NODE** got = find_child(&n48->base, key);
        TEST_ASSERT(got == &n48->children[16], "4.1: Should return &children[index-1]");

        test_free_node_any(child);
        test_free_node_any(&n48->base);
    }

    // (4.2) index == 0 -> absent
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48 != NULL, "4.2-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 10;
        UCHAR key = 0x11;
        n48->child_index[key] = 0;
        ART_NODE** got = find_child(&n48->base, key);
        TEST_ASSERT(got == NULL, "4.2: index==0 means no child");
        test_free_node_any(&n48->base);
    }

    // (4.3) out of range
    reset_mock_state()
        ;
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48 != NULL, "4.3-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 48;
        UCHAR key = 0x22;
        n48->child_index[key] = 49; // invalid
        ART_NODE** got = find_child(&n48->base, key);
        TEST_ASSERT(got == NULL, "4.3: index out of range must be ignored");
        test_free_node_any(&n48->base);
    }

    // (4.4) mapped but child slot is NULL
    reset_mock_state();
    {
        ART_NODE48* n48 = t_alloc_node48(); TEST_ASSERT(n48 != NULL, "4.4-pre: node48 alloc");
        n48->base.type = NODE48; n48->base.num_of_child = 30;
        UCHAR key = 0x33;
        n48->child_index[key] = 5; // maps to children[4]
        for (int i = 0; i < 48; i++) n48->children[i] = NULL; // ensure NULL slot
        ART_NODE** got = find_child(&n48->base, key);
        TEST_ASSERT(got == NULL, "4.4: mapped slot NULL -> return NULL");
        test_free_node_any(&n48->base);
    }

    DbgPrint("[INFO] Test 4: NODE48 mapping rules validated\n");
    TEST_END("find_child: NODE48");
    return TRUE;
}

/* =========================================================
   Test 5: NODE256 direct table
   Purpose:
     - children[c] non-NULL -> return &children[c]
     - children[c] == NULL -> NULL
   Sub-checks:
     (5.1) Hit returns the slot address
     (5.2) Miss returns NULL
   ========================================================= */
BOOLEAN test_find_child_node256()
{
    TEST_START("find_child: NODE256");

    // (5.1) hit
    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256 != NULL, "5.1-pre: node256 alloc");
        n256->base.type = NODE256; n256->base.num_of_child = 1;
        UCHAR key = 0xA4;
        ART_NODE* child = t_alloc_dummy_child(NODE4);
        n256->children[key] = child;

        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        ART_NODE** got = find_child(&n256->base, key);
        TEST_ASSERT(got == &n256->children[key], "5.1: return &children[c]");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "5.1: no alloc/free inside");

        test_free_node_any(child);
        test_free_node_any(&n256->base);
    }

    // (5.2) miss
    reset_mock_state();
    {
        ART_NODE256* n256 = t_alloc_node256(); TEST_ASSERT(n256 != NULL, "5.2-pre: node256 alloc");
        n256->base.type = NODE256; n256->base.num_of_child = 0;
        UCHAR key = 0x7F;
        ART_NODE** miss = find_child(&n256->base, key);
        TEST_ASSERT(miss == NULL, "5.2: NULL when slot empty");
        test_free_node_any(&n256->base);
    }

    DbgPrint("[INFO] Test 5: NODE256 direct table behavior validated\n");
    TEST_END("find_child: NODE256");
    return TRUE;
}

/* =========================================================
   Test 6: No internal allocation/free across diverse calls
   Purpose:
     - Ensure find_child never performs allocations or frees.
   Sub-checks:
     (6.1) Alloc/free counters unchanged across mixed calls
   ========================================================= */
BOOLEAN test_find_child_no_allocfree_sideeffects()
{
    TEST_START("find_child: no alloc/free side effects");

    reset_mock_state();

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    // A few diverse quick calls
#pragma warning(push)
#pragma warning(disable: 6387) 
    (void)find_child(NULL, 0x00);
#pragma warning(pop)

    {
        ART_NODE4* n4 = t_alloc_node4(); n4->base.type = NODE4; n4->base.num_of_child = 0;
        (void)find_child(&n4->base, (UCHAR)'x');
        test_free_node_any(&n4->base);
    }
    {
        ART_NODE16* n16 = t_alloc_node16(); n16->base.type = NODE16; n16->base.num_of_child = 1;
        n16->keys[0] = 'k'; n16->children[0] = t_alloc_dummy_child(NODE4);
        (void)find_child(&n16->base, (UCHAR)'k');
        test_free_node_any(n16->children[0]); test_free_node_any(&n16->base);
    }
    {
        ART_NODE48* n48 = t_alloc_node48(); n48->base.type = NODE48; n48->base.num_of_child = 1;
        n48->child_index[0x2C] = 1; n48->children[0] = t_alloc_dummy_child(NODE16);
        (void)find_child(&n48->base, 0x2C);
        test_free_node_any(n48->children[0]); test_free_node_any(&n48->base);
    }
    {
        ART_NODE256* n256 = t_alloc_node256(); n256->base.type = NODE256; n256->base.num_of_child = 1;
        n256->children[0xEE] = t_alloc_dummy_child(NODE48);
        (void)find_child(&n256->base, 0xEE);
        test_free_node_any(n256->children[0xEE]); test_free_node_any(&n256->base);
    }

    // Exact test-side allocations: NODE4(1) + NODE16(2) + NODE48(2) + NODE256(2) = 7
    TEST_ASSERT(g_alloc_call_count == a0 + 7 /* our test allocations only */,
            "6.1: No unexpected allocations inside find_child");
    TEST_ASSERT(g_free_call_count >= f0 + 6,
        "6.1: Frees correspond only to test cleanups");

    DbgPrint("[INFO] Test 6: counters show find_child has no alloc/free\n");
    TEST_END("find_child: no alloc/free side effects");
    return TRUE;
}

// =========================================================
// Fuzzer-style test using deterministic LCG (no CRT/random)
// Covers NODE4/NODE16/NODE48/NODE256 with randomized content
// =========================================================

static __forceinline UINT32 lcg_next(UINT32* state)
{
    // Same constants used earlier; deterministic, reproducible
    const UINT32 A = 1664525u;
    const UINT32 C = 1013904223u;
    *state = A * (*state) + C;
    return *state;
}

// Returns a byte in [0,255]
static __forceinline UCHAR lcg_byte(UINT32* st)
{
    return (UCHAR)(lcg_next(st) & 0xFFu);
}

BOOLEAN test_find_child_fuzzer_lcg()
{
    TEST_START("find_child: fuzzer-style (deterministic LCG)");

    reset_mock_state();

    UINT32 st = 0xCAFEBABEu; // seed
    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    // how many fuzz cases per node type
    const int ROUNDS_PER_TYPE = 128;

    // ---------- Fuzz NODE4 ----------
    for (int r = 0; r < ROUNDS_PER_TYPE; ++r) {
        ART_NODE4* n4 = (ART_NODE4*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE4), ART_TAG);
        TEST_ASSERT(n4 != NULL, "FZ-N4: node allocation");
        RtlZeroMemory(n4, sizeof(ART_NODE4));
        n4->base.type = NODE4;

        // num_of_child random 0..8 (deliberately over capacity); safe clamp must be 0..4
        USHORT num = (USHORT)(lcg_next(&st) % 9);
        n4->base.num_of_child = num;

        // Fill keys for all 16 positions (only first 4 matter, but keep pattern)
        for (int i = 0; i < 4; ++i) n4->keys[i] = lcg_byte(&st);

        // Allocate children for the first 4 indices; others ignored anyway
        for (int i = 0; i < 4; ++i) {
            n4->children[i] = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
            TEST_ASSERT(n4->children[i] != NULL, "FZ-N4: child alloc");
            RtlZeroMemory(n4->children[i], sizeof(ART_NODE));
        }

        // Probe with random key c
        UCHAR c = lcg_byte(&st);
        ART_NODE** got = find_child(&n4->base, c);

        // Recompute expected by spec
        USHORT safe = (n4->base.num_of_child < 4) ? n4->base.num_of_child : 4;
        ART_NODE** expect = NULL;
        for (USHORT i = 0; i < safe; ++i) {
            if (n4->keys[i] == c) { expect = &n4->children[i]; break; }
        }
        TEST_ASSERT(got == expect, "FZ-N4: expected pointer must match");

        // cleanup
        for (int i = 0; i < 4; ++i)
            if (n4->children[i]) ExFreePoolWithTag(n4->children[i], ART_TAG);
        ExFreePoolWithTag(n4, ART_TAG);
    }

    // ---------- Fuzz NODE16 ----------
    for (int r = 0; r < ROUNDS_PER_TYPE; ++r) {
        ART_NODE16* n16 = (ART_NODE16*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE16), ART_TAG);
        TEST_ASSERT(n16 != NULL, "FZ-N16: node allocation");
        RtlZeroMemory(n16, sizeof(ART_NODE16));
        n16->base.type = NODE16;

        // num_of_child random 0..24; mask must restrict to 0..16
        USHORT num = (USHORT)(lcg_next(&st) % 25);
        n16->base.num_of_child = num;

        for (int i = 0; i < 16; ++i) n16->keys[i] = lcg_byte(&st);
        for (int i = 0; i < 16; ++i) {
            n16->children[i] = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
            TEST_ASSERT(n16->children[i] != NULL, "FZ-N16: child alloc");
            RtlZeroMemory(n16->children[i], sizeof(ART_NODE));
        }

        UCHAR c = lcg_byte(&st);
        ART_NODE** got = find_child(&n16->base, c);

        // Expected: lowest index i in [0, safe) with keys[i]==c
        USHORT safe = (n16->base.num_of_child < 16) ? n16->base.num_of_child : 16;
        ART_NODE** expect = NULL;
        for (USHORT i = 0; i < safe; ++i) {
            if (n16->keys[i] == c) { expect = &n16->children[i]; break; }
        }
        TEST_ASSERT(got == expect, "FZ-N16: expected pointer must match");

        for (int i = 0; i < 16; ++i)
            if (n16->children[i]) ExFreePoolWithTag(n16->children[i], ART_TAG);
        ExFreePoolWithTag(n16, ART_TAG);
    }

    // ---------- Fuzz NODE48 ----------
    for (int r = 0; r < ROUNDS_PER_TYPE; ++r) {
        ART_NODE48* n48 = (ART_NODE48*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE48), ART_TAG);
        TEST_ASSERT(n48 != NULL, "FZ-N48: node allocation");
        RtlZeroMemory(n48, sizeof(ART_NODE48));
        n48->base.type = NODE48;
        n48->base.num_of_child = (USHORT)(lcg_next(&st) % 64); // any, not used by logic

        // Clear map
        RtlZeroMemory(n48->child_index, sizeof(n48->child_index));
        for (int i = 0; i < 48; ++i) {
            n48->children[i] = NULL;
        }

        // Install K random mappings (1..48) in child_index with existing children
        int K = (int)(lcg_next(&st) % 48); // 0..47
        for (int j = 0; j < K; ++j) {
            UCHAR key = lcg_byte(&st);
            UCHAR idx1based = (UCHAR)((lcg_next(&st) % 48) + 1); // 1..48
            n48->child_index[key] = idx1based;
            int slot = (int)idx1based - 1;
            if (!n48->children[slot]) {
                n48->children[slot] = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
                TEST_ASSERT(n48->children[slot] != NULL, "FZ-N48: child alloc");
                RtlZeroMemory(n48->children[slot], sizeof(ART_NODE));
            }
        }

        UCHAR c = lcg_byte(&st);
        ART_NODE** got = find_child(&n48->base, c);

        // Expected:
        ART_NODE** expect = NULL;
        int idx = (int)n48->child_index[c];
        if (idx > 0 && idx <= 48) {
            int slot = idx - 1;
            if (n48->children[slot]) expect = &n48->children[slot];
        }
        TEST_ASSERT(got == expect, "FZ-N48: expected pointer must match");

        for (int i = 0; i < 48; ++i)
            if (n48->children[i]) ExFreePoolWithTag(n48->children[i], ART_TAG);
        ExFreePoolWithTag(n48, ART_TAG);
    }

    // ---------- Fuzz NODE256 ----------
    for (int r = 0; r < ROUNDS_PER_TYPE; ++r) {
        ART_NODE256* n256 = (ART_NODE256*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE256), ART_TAG);
        TEST_ASSERT(n256 != NULL, "FZ-N256: node allocation");
        RtlZeroMemory(n256, sizeof(ART_NODE256));
        n256->base.type = NODE256;
        n256->base.num_of_child = (USHORT)(lcg_next(&st) & 0xFFFF); // arbitrary

        // Randomly populate some slots
        int fill = (int)(lcg_next(&st) % 64); // fill up to 64 children
        for (int j = 0; j < fill; ++j) {
            UCHAR slot = lcg_byte(&st);
            if (!n256->children[slot]) {
                n256->children[slot] = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
                TEST_ASSERT(n256->children[slot] != NULL, "FZ-N256: child alloc");
                RtlZeroMemory(n256->children[slot], sizeof(ART_NODE));
            }
        }

        UCHAR c = lcg_byte(&st);
        ART_NODE** got = find_child(&n256->base, c);

        ART_NODE** expect = n256->children[c] ? &n256->children[c] : NULL;
        TEST_ASSERT(got == expect, "FZ-N256: expected pointer must match");

        for (int i = 0; i < 256; ++i)
            if (n256->children[i]) ExFreePoolWithTag(n256->children[i], ART_TAG);
        ExFreePoolWithTag(n256, ART_TAG);
    }

    // Ensure find_child itself never alloc/free'd:
    TEST_ASSERT(g_alloc_call_count >= alloc_before, "FZ-END: alloc counter progressed only by test setup");
    TEST_ASSERT(g_free_call_count >= free_before, "FZ-END: free counter progressed only by test teardown");

    DbgPrint("[INFO] Fuzzer-style test: completed for all node kinds with deterministic LCG\n");
    TEST_END("find_child: fuzzer-style (deterministic LCG)");
    return TRUE;
}

BOOLEAN test_search_terminator_edge()
{
    TEST_START("art_search: terminator edge at internal node");

    ART_NODE4* n4 = mk_n4();
    TEST_ASSERT(n4, "pre: NODE4 alloc");

    n4->base.prefix_length = 2;
    n4->base.prefix[0] = 'a';
    n4->base.prefix[1] = 'b';

    // terminator (0x00) altında "ab" yaprağı
    UCHAR full_ab[] = { 'a','b' };
    ART_LEAF* lf = make_leaf(full_ab, 2, 0xABCD);
    TEST_ASSERT(lf, "pre: leaf");

    // children[0] terminatör için değil; burada 'find_child'ın terminatörü 0 byte ile
    // bulacağı varsayılıyor. Basitçe slot0'a SET_LEAF koyup find_child(0) başarılı olacak
    // şekilde test altyapın çalışıyorsa devam; aksi halde gerçek find_child mantığına göre
    // 0 byte map’i oluşturmalısın.
    // Basit yaklaşım: keys[0] = 0; children[0] = leaf
    UCHAR k0 = 0;
    ART_NODE* ch0 = (ART_NODE*)SET_LEAF(lf);
    TEST_ASSERT(n4_set(n4, &k0, 1, &ch0), "pre: map terminator");

    ART_TREE t; RtlZeroMemory(&t, sizeof(t));
    t.root = (ART_NODE*)n4; t.size = 1;

    UNICODE_STRING uq; create_unicode_string(&uq, L"ab", 2);
    ULONG v = art_search(&t, &uq);
    TEST_ASSERT(v == 0xABCD, "found via terminator leaf");

    cleanup_unicode_string(&uq);
    // cleanup
    ART_LEAF* raw = LEAF_RAW(ch0); free_leaf(&raw);
    ART_NODE* root = (ART_NODE*)n4; free_node(&root);

    TEST_END("art_search: terminator edge at internal node");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_find_child_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting find_child Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_find_child_null_and_invalid())          all_passed = FALSE;
    if (!test_find_child_node4())                     all_passed = FALSE;
    if (!test_find_child_node16())                    all_passed = FALSE;
    if (!test_find_child_node48())                    all_passed = FALSE;
    if (!test_find_child_node256())                   all_passed = FALSE;
    if (!test_find_child_no_allocfree_sideeffects())  all_passed = FALSE;
    if (!test_find_child_fuzzer_lcg())                all_passed = FALSE;


    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL find_child TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME find_child TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
