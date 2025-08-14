#if UNIT_TEST

#include "test_art.h"

// SUT
ULONG art_search(_In_ CONST ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

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

// =======================================
// Test 1: Guard parameters
// =======================================
BOOLEAN test_search_guard_params()
{
    TEST_START("art_search: guard params");

#pragma warning(push)
#pragma warning(disable: 6387)
    ULONG v1 = art_search(NULL, NULL);
#pragma warning(pop)
    TEST_ASSERT(v1 == POLICY_NONE, "1.1: NULL tree+key -> POLICY_NONE");

    ART_TREE t; dz(&t, sizeof(t));
    UNICODE_STRING u; dz(&u, sizeof(u));
    ULONG v2 = art_search(&t, NULL);
    TEST_ASSERT(v2 == POLICY_NONE, "1.2: NULL key -> POLICY_NONE");

    TEST_END("art_search: guard params");
    return TRUE;
}

// =======================================
// Test 2: Empty tree
// =======================================
BOOLEAN test_search_empty_tree()
{
    TEST_START("art_search: empty tree");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = NULL; t.size = 0;

    WCHAR w[] = L"a";
    UNICODE_STRING u; create_unicode_string(&u, w, 1);

    ULONG v = art_search(&t, &u);
    TEST_ASSERT(v == POLICY_NONE, "2.1: empty tree -> POLICY_NONE");

    cleanup_unicode_string(&u);
    TEST_END("art_search: empty tree");
    return TRUE;
}

// =======================================
// Test 3: Unicode->UTF8 conversion failure
// (overly long path triggers early reject in unicode_to_utf8)
// =======================================
BOOLEAN test_search_unicode_to_utf8_failure()
{
    TEST_START("art_search: unicode_to_utf8 failure");

#ifndef MAXUSHORT
#define MAXUSHORT 0xFFFF
#endif

#ifndef MAX_KEY_LENGTH
    LOG_MSG("[INFO] MAX_KEY_LENGTH not defined; skipping.\n");
    TEST_END("art_search: unicode_to_utf8 failure");
    return TRUE;
#else
    // SUT için küçük bir ağaç: kök tek yaprak "x"
    ART_TREE t; RtlZeroMemory(&t, sizeof(t));
    {
        UCHAR kx = 'x';
        ART_LEAF* lf0 = make_leaf(&kx, 1, 123);
        TEST_ASSERT(lf0 != NULL, "pre: leaf alloc");
        t.root = (ART_NODE*)SET_LEAF(lf0);
        t.size = 1;
    }

    // --- Güvenli şekilde "fazla uzun" Unicode anahtar üret ---
    // UNICODE_STRING.Length = L * sizeof(WCHAR) (USHORT). L, hem MAX_KEY_LENGTH+1 olmalı,
    // hem de USHORT sınırına (ve NUL için +1) sığmalı.
    const size_t maxL_by_unicode = (MAXUSHORT / sizeof(WCHAR)) - 1; // NUL için 1 bırak
    size_t Lsz = (size_t)MAX_KEY_LENGTH + 1;                        // overlong hedefi
    if (Lsz > maxL_by_unicode) {
        LOG_MSG("[INFO] Cannot build overlong UNICODE (MAX_KEY_LENGTH too large); skipping.\n");
        // Temizlik
        ART_LEAF* lf = LEAF_RAW(t.root); free_leaf(&lf); t.root = NULL; t.size = 0;
        TEST_END("art_search: unicode_to_utf8 failure");
        return TRUE; // skip
    }
    const USHORT L = (USHORT)Lsz;

    // Buffer ayır, 'a' ile doldur
    PWCHAR buf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)(L + 1) * sizeof(WCHAR), ART_TAG);
    TEST_ASSERT(buf != NULL, "pre: allocate overlong unicode");
    for (USHORT i = 0; i < L; ++i) buf[i] = L'a';
    buf[L] = L'\0';

    UNICODE_STRING bogus;
    bogus.Buffer = buf;
    bogus.Length = (USHORT)(L * sizeof(WCHAR));
    bogus.MaximumLength = (USHORT)((L + 1) * sizeof(WCHAR));

    // Beklenti: unicode_to_utf8, required_length > MAX_KEY_LENGTH olduğu için NULL döner
    ULONG v = art_search(&t, &bogus);
    TEST_ASSERT(v == POLICY_NONE, "3.1: conversion failure -> POLICY_NONE");

    // Temizlik
    ExFreePool2(buf, ART_TAG, NULL, 0);
    ART_LEAF* lf = LEAF_RAW(t.root); free_leaf(&lf);
    t.root = NULL; t.size = 0;

    TEST_END("art_search: unicode_to_utf8 failure");
    return TRUE;
#endif
}


// =======================================
// Test 4: Empty UTF-8 after conversion (input empty)
// =======================================
BOOLEAN test_search_empty_key_after_conversion()
{
    TEST_START("art_search: empty key after conversion");

    ART_TREE t; dz(&t, sizeof(t));
    // Put something in tree; function should early-out on empty key anyway.
    UCHAR k = 'k';
    ART_LEAF* lf = make_leaf(&k, 1, 0x42);
    t.root = (ART_NODE*)SET_LEAF(lf);
    t.size = 1;

    UNICODE_STRING u; create_unicode_string(&u, L"", 0); // Length == 0

    ULONG v = art_search(&t, &u);
    TEST_ASSERT(v == POLICY_NONE, "4.1: empty input key -> POLICY_NONE");

    cleanup_unicode_string(&u);
    // cleanup leaf
    ART_LEAF* raw = LEAF_RAW(t.root);
    free_leaf(&raw);
    t.root = NULL; t.size = 0;

    TEST_END("art_search: empty key after conversion");
    return TRUE;
}

// =======================================
// Test 5: Exact match — root is a leaf
// =======================================
BOOLEAN test_search_exact_leaf_root()
{
    TEST_START("art_search: exact match (leaf root)");

    UCHAR k = 'x';
    ART_LEAF* leaf = make_leaf(&k, 1, 0xDEAD);
    TEST_ASSERT(leaf != NULL, "5-pre: leaf allocated");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)SET_LEAF(leaf);
    t.size = 1;

    UNICODE_STRING u; create_unicode_string(&u, L"x", 1);
    ULONG v = art_search(&t, &u);
    TEST_ASSERT(v == 0xDEAD, "5.1: exact hit returns stored value");

    cleanup_unicode_string(&u);
    // cleanup
    ART_LEAF* raw = LEAF_RAW(t.root);
    free_leaf(&raw); t.root = NULL; t.size = 0;

    TEST_END("art_search: exact match (leaf root)");
    return TRUE;
}

// =======================================
// Test 6: NODE4 path to a leaf (success and miss)
// =======================================
BOOLEAN test_search_node4_path()
{
    TEST_START("art_search: NODE4 path");

    ART_NODE4* n4 = mk_n4();
    TEST_ASSERT(n4 != NULL, "6-pre: NODE4 allocated");

    UCHAR a = 'a', z = 'z';
    ART_LEAF* la = make_leaf(&a, 1, 0x0A);
    ART_LEAF* lz = make_leaf(&z, 1, 0xFFFFFFFF); // 0x5A? choose a value that's valid hex

    ULONG ZVAL = 0x5A5A;
    free_leaf(&lz); lz = make_leaf(&z, 1, ZVAL);
    TEST_ASSERT(la && lz, "6-pre: leaves allocated");

    ART_NODE* ch[2] = { (ART_NODE*)SET_LEAF(la), (ART_NODE*)SET_LEAF(lz) };
    UCHAR keys[2] = { a, z };
    TEST_ASSERT(n4_set(n4, keys, 2, ch), "6-pre: NODE4 wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)n4;
    t.size = 2;

    UNICODE_STRING uA; create_unicode_string(&uA, L"a", 1);
    ULONG va = art_search(&t, &uA);
    TEST_ASSERT(va == 0x0A, "6.1: hit 'a'");

    UNICODE_STRING uZ; create_unicode_string(&uZ, L"z", 1);
    ULONG vz = art_search(&t, &uZ);
    TEST_ASSERT(vz == ZVAL, "6.2: hit 'z'");

    UNICODE_STRING uB; create_unicode_string(&uB, L"b", 1);
    ULONG vb = art_search(&t, &uB);
    TEST_ASSERT(vb == POLICY_NONE, "6.3: miss 'b' -> POLICY_NONE");

    cleanup_unicode_string(&uA);
    cleanup_unicode_string(&uZ);
    cleanup_unicode_string(&uB);

    // cleanup leaves
    ART_LEAF* r0 = LEAF_RAW(ch[0]); free_leaf(&r0);
    ART_LEAF* r1 = LEAF_RAW(ch[1]); free_leaf(&r1);
    ART_NODE* root = (ART_NODE*)n4; free_node(&root);

    TEST_END("art_search: NODE4 path");
    return TRUE;
}

// =======================================
// Test 7: Prefix handling — match, mismatch, key-too-short
// =======================================
BOOLEAN test_search_prefix_handling()
{
    TEST_START("art_search: prefix handling");

    // Build NODE4 whose base.prefix="ab" and a single child 'c'->leaf "abc"
    ART_NODE4* n4 = mk_n4();
    TEST_ASSERT(n4 != NULL, "7-pre: NODE4 allocated");

    // Set prefix "ab"
    n4->base.prefix_length = 2;
    n4->base.prefix[0] = 'a';
    n4->base.prefix[1] = 'b';

    UCHAR key_abc[] = { 'a','b','c' };
    ART_LEAF* leaf = make_leaf(key_abc, 3, 0xABC);
    TEST_ASSERT(leaf != NULL, "7-pre: leaf allocated");

    ART_NODE* ch = (ART_NODE*)SET_LEAF(leaf);
    UCHAR child_key = 'c';
    TEST_ASSERT(n4_set(n4, &child_key, 1, &ch), "7-pre: child wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)n4;
    t.size = 1;

    // 7.1: exact match "abc"
    WCHAR wABC[3] = { L'a', L'b', L'c' };
    UNICODE_STRING uABC; create_unicode_string(&uABC, wABC, 3);
    ULONG v1 = art_search(&t, &uABC);
    TEST_ASSERT(v1 == 0xABC, "7.1: prefix matches then child -> leaf");

    // 7.2: prefix mismatch "abX"
    WCHAR wABX[3] = { L'a', L'b', L'X' };
    UNICODE_STRING uABX; create_unicode_string(&uABX, wABX, 3);
    ULONG v2 = art_search(&t, &uABX);
    TEST_ASSERT(v2 == POLICY_NONE, "7.2: mismatch under prefix -> none");

    // 7.3: key too short "ab" (no child step possible)
    WCHAR wAB[2] = { L'a', L'b' };
    UNICODE_STRING uAB; create_unicode_string(&uAB, wAB, 2);
    ULONG v3 = art_search(&t, &uAB);
    TEST_ASSERT(v3 == POLICY_NONE, "7.3: key exhausted after prefix -> none");

    cleanup_unicode_string(&uABC);
    cleanup_unicode_string(&uABX);
    cleanup_unicode_string(&uAB);

    // cleanup
    ART_LEAF* raw = LEAF_RAW(ch);
    free_leaf(&raw);
    ART_NODE* root = (ART_NODE*)n4;
    free_node(&root);
    t.root = NULL;
    t.size = 0;

    TEST_END("art_search: prefix handling");
    return TRUE;
}

// =======================================
// Test 8: NODE48 and NODE256 search paths
// =======================================
BOOLEAN test_search_node48_and_node256()
{
    TEST_START("art_search: NODE48 & NODE256");

    // NODE48 with two leaves at keys 5 and 200
    ART_NODE48* n48 = mk_n48(); TEST_ASSERT(n48, "8-pre: NODE48 allocated");
    UCHAR kb5 = 5, kb200 = 200;
    ART_LEAF* l5 = make_leaf(&kb5, 1, 0x0505);
    ART_LEAF* l200 = make_leaf(&kb200, 1, 0xC8C8);
    TEST_ASSERT(l5 && l200, "8-pre: two leaves");

    ART_NODE* ch48[2] = { (ART_NODE*)SET_LEAF(l5), (ART_NODE*)SET_LEAF(l200) };
    UCHAR map[2] = { 5, 200 };
    TEST_ASSERT(n48_map(n48, map, 2, ch48), "8-pre: NODE48 wired");

    // NODE256 with one leaf at index 7
    ART_NODE256* n256 = mk_n256(); TEST_ASSERT(n256, "8-pre: NODE256 allocated");
    UCHAR idx = 7; UCHAR k7 = 7;
    ART_LEAF* l7 = make_leaf(&k7, 1, 0x0707);
    TEST_ASSERT(l7, "8-pre: leaf 7");
    ART_NODE* ch256[1] = { (ART_NODE*)SET_LEAF(l7) };
    TEST_ASSERT(n256_set(n256, &idx, 1, ch256), "8-pre: NODE256 wired");

    // Put them under a NODE16: keys {10 -> n48, 11 -> n256}
    ART_NODE16* root16 = mk_n16(); TEST_ASSERT(root16, "8-pre: NODE16 root");
    UCHAR rkeys[2] = { 10, 11 };
    ART_NODE* rch[2] = { (ART_NODE*)n48, (ART_NODE*)n256 };
    TEST_ASSERT(n16_set(root16, rkeys, 2, rch), "8-pre: NODE16 wired");

    ART_TREE t; dz(&t, sizeof(t));
    t.root = (ART_NODE*)root16;
    t.size = 3;

    // Key "\x0A\x05"  => 10 -> NODE48, 5 -> leaf(0x0505)
    WCHAR wA[2]; wA[0] = (WCHAR)10; wA[1] = (WCHAR)5;
    UNICODE_STRING uA; create_unicode_string(&uA, wA, 2);
    ULONG vA = art_search(&t, &uA);
    TEST_ASSERT(vA == 0x0505, "8.1: NODE16->NODE48->leaf hit");
    cleanup_unicode_string(&uA);

    // Key "\x0B\x07"  => 11 -> NODE256, 7 -> leaf(0x0707)
    WCHAR wB[2]; wB[0] = (WCHAR)11; wB[1] = (WCHAR)7;
    UNICODE_STRING uB; create_unicode_string(&uB, wB, 2);
    ULONG vB = art_search(&t, &uB);
    TEST_ASSERT(vB == 0x0707, "8.2: NODE16->NODE256->leaf hit");
    cleanup_unicode_string(&uB);

    // Miss: "\x0A\x06" (NODE48 altında 6 yok)
    WCHAR wM[2]; wM[0] = (WCHAR)10; wM[1] = (WCHAR)6;
    UNICODE_STRING uM; create_unicode_string(&uM, wM, 2);
    ULONG vM = art_search(&t, &uM);
    TEST_ASSERT(vM == POLICY_NONE, "8.3: child not found under NODE48");
    cleanup_unicode_string(&uM);

    // cleanup all leaves/nodes
    ART_LEAF* rl5 = LEAF_RAW(ch48[0]);  free_leaf(&rl5);
    ART_LEAF* rl200 = LEAF_RAW(ch48[1]);  free_leaf(&rl200);
    ART_LEAF* rl7 = LEAF_RAW(ch256[0]); free_leaf(&rl7);

    ART_NODE* n = (ART_NODE*)n48;   free_node(&n);
    n = (ART_NODE*)n256;            free_node(&n);
    n = (ART_NODE*)root16;          free_node(&n);

    TEST_END("art_search: NODE48 & NODE256");
    return TRUE;
}

// =======================================
// Test 9: Recursion depth overflow guard
// =======================================
BOOLEAN test_search_depth_overflow_guard()
{
    TEST_START("art_search: recursion depth overflow guard");

    // Build a very deep chain of NODE4s: each step key = 'a'
    ART_NODE* root = (ART_NODE*)mk_n4();
    TEST_ASSERT(root, "9-pre: root NODE4");

    ART_NODE* cur = root;
    const UCHAR step = 'a';
    for (USHORT i = 0; i < (USHORT)(MAX_RECURSION_DEPTH + 4); i++) {
        ART_NODE4* n4 = (ART_NODE4*)cur;
        ART_NODE* next;
        if (i == (USHORT)(MAX_RECURSION_DEPTH + 3)) {
            UCHAR tail = step;                      // <-- geçici yerine yerel değişken
            ART_LEAF* lf = make_leaf(&tail, 1, 0xAA);
            TEST_ASSERT(lf, "9-pre: tail leaf");
            next = (ART_NODE*)SET_LEAF(lf);
        }
        else {
            next = (ART_NODE*)mk_n4();
            TEST_ASSERT(next, "9-pre: intermediate NODE4");
        }
        ART_NODE* child = next;
        TEST_ASSERT(n4_set(n4, &step, 1, &child), "9-pre: link");
        if (!IS_LEAF(next)) cur = next;
    }

    ART_TREE t; dz(&t, sizeof(t)); t.root = root; t.size = 1;

    // Build Unicode key "aaaa..." (MAX_RECURSION_DEPTH+4 times)
    const USHORT KLEN = (USHORT)(MAX_RECURSION_DEPTH + 4);
    UNICODE_STRING u; dz(&u, sizeof(u));
    u.Length = KLEN * sizeof(WCHAR);
    u.MaximumLength = u.Length + sizeof(WCHAR);
    u.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, u.MaximumLength, ART_TAG);
    if (!u.Buffer) {
        TEST_END("art_search: recursion depth overflow guard");
        return TRUE; // skip if no memory
    }
    for (USHORT i = 0; i < KLEN; i++) { u.Buffer[i] = L'a'; }
    u.Buffer[KLEN] = L'\0';

    ULONG v = art_search(&t, &u);
    TEST_ASSERT(v == POLICY_NONE, "9.1: search aborts, not crashing, returns none");

    cleanup_unicode_string(&u);

    // cleanup the chain manually: delete all
    ULONG leaf_count = 0;
    ULONG node_count = 0;
    (void)recursive_delete_all_internal(&t, &t.root, &leaf_count, &node_count, 0); // <-- 5 arg
    t.root = NULL;
    t.size = 0;

    TEST_END("art_search: recursion depth overflow guard");
    return TRUE;
}

// =======================================
// Suite runner
// =======================================
NTSTATUS run_all_art_search_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_search() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_search_guard_params())               all = FALSE; // (1)
    if (!test_search_empty_tree())                 all = FALSE; // (2)
    if (!test_search_unicode_to_utf8_failure())    all = FALSE; // (3)
    if (!test_search_empty_key_after_conversion()) all = FALSE; // (4)
    if (!test_search_exact_leaf_root())            all = FALSE; // (5)
    if (!test_search_node4_path())                 all = FALSE; // (6)
    if (!test_search_prefix_handling())            all = FALSE; // (7)
    if (!test_search_node48_and_node256())         all = FALSE; // (8)
    if (!test_search_depth_overflow_guard())       all = FALSE; // (9)

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL art_search() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_search() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif
