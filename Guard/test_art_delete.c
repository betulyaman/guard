#include "test_art.h"

// Under test
ULONG art_delete(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

// ------- tiny helpers for this file (no CRT) -------
static VOID ad_zero(void* p, SIZE_T n) { RtlZeroMemory(p, n); }

// Make a tree with a single leaf as root for given 8-bit key
static BOOLEAN ad_make_single_leaf_tree(ART_TREE* tree, CONST UCHAR* key, USHORT key_len, ULONG val)
{
    ad_zero(tree, sizeof(*tree));
    ART_LEAF* lf = make_leaf((const PUCHAR)key, key_len, val);
    if (!lf) return FALSE;
    tree->root = (ART_NODE*)SET_LEAF(lf);
    tree->size = 1;
    return TRUE;
}

// Build NODE4 root with two 1-byte keys (sorted) , children are leaves
static BOOLEAN ad_make_node4_two_leaves(ART_TREE* tree,
    UCHAR k0, ULONG v0,
    UCHAR k1, ULONG v1)
{
    ad_zero(tree, sizeof(*tree));
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return FALSE;

    ART_LEAF* l0 = make_leaf(&k0, 1, v0);
    ART_LEAF* l1 = make_leaf(&k1, 1, v1);
    if (!l0 || !l1) {
        if (l0) free_leaf(&l0);
        if (l1) free_leaf(&l1);
        free_node((ART_NODE**)&n4);
        return FALSE;
    }

    // Keep keys sorted
    if (k0 <= k1) {
        n4->keys[0] = k0; n4->children[0] = (ART_NODE*)SET_LEAF(l0);
        n4->keys[1] = k1; n4->children[1] = (ART_NODE*)SET_LEAF(l1);
    }
    else {
        n4->keys[0] = k1; n4->children[0] = (ART_NODE*)SET_LEAF(l1);
        n4->keys[1] = k0; n4->children[1] = (ART_NODE*)SET_LEAF(l0);
    }
    n4->base.num_of_child = 2;

    tree->root = (ART_NODE*)n4;
    tree->size = 2;
    return TRUE;
}

// NODE4 with prefix {pfx} and single child under byte c -> leaf for key {pfx,c}
static BOOLEAN ad_make_prefixed_node4_one_leaf(ART_TREE* tree, UCHAR pfx, UCHAR c, ULONG val)
{
    ad_zero(tree, sizeof(*tree));
    ART_NODE4* n4 = (ART_NODE4*)art_create_node(NODE4);
    if (!n4) return FALSE;
    n4->base.type = NODE4;
    n4->base.prefix_length = 1;
    ad_zero(n4->base.prefix, sizeof(n4->base.prefix));
    n4->base.prefix[0] = pfx;

    UCHAR full[2] = { pfx, c };
    ART_LEAF* lf = make_leaf(full, 2, val);
    if (!lf) { free_node((ART_NODE**)&n4); return FALSE; }

    n4->keys[0] = c;
    n4->children[0] = (ART_NODE*)SET_LEAF(lf);
    n4->base.num_of_child = 1;

    tree->root = (ART_NODE*)n4;
    tree->size = 1;
    return TRUE;
}

// Free entire tree (handles leaves and internal nodes)
static VOID ad_free_tree(ART_NODE** pref)
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
        for (USHORT i = 0; i < 4; i++) {
            ART_NODE* ch = p->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ad_free_tree(&ch);
            }
        }
        break;
    }
    case NODE16: {
        ART_NODE16* p = (ART_NODE16*)n;
        for (USHORT i = 0; i < 16; i++) {
            ART_NODE* ch = p->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ad_free_tree(&ch);
            }
        }
        break;
    }
    case NODE48: {
        ART_NODE48* p = (ART_NODE48*)n;
        for (USHORT i = 0; i < 48; i++) {
            ART_NODE* ch = p->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ad_free_tree(&ch);
            }
        }
        break;
    }
    case NODE256: {
        ART_NODE256* p = (ART_NODE256*)n;
        for (USHORT i = 0; i < 256; i++) {
            ART_NODE* ch = p->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
            }
            else {
                ad_free_tree(&ch);
            }
        }
        break;
    }
    default: break;
    }

    free_node(pref);
}

// Helper: create + cleanup UNICODE strings
static NTSTATUS ad_make_unicode(UNICODE_STRING* dst, PCWSTR src, ULONG chars)
{
    dst->Length = (USHORT)(chars * sizeof(WCHAR));
    dst->MaximumLength = dst->Length + sizeof(WCHAR);
    dst->Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, dst->MaximumLength, ART_TAG);
    if (!dst->Buffer) return STATUS_NO_MEMORY;
    if (src && chars) RtlCopyMemory(dst->Buffer, src, dst->Length);
    dst->Buffer[chars] = L'\0';
    return STATUS_SUCCESS;
}
static VOID ad_free_unicode(UNICODE_STRING* s)
{
    if (s->Buffer) {
        ExFreePool2(s->Buffer, ART_TAG, NULL, 0);
        s->Buffer = NULL;
    }
    s->Length = s->MaximumLength = 0;
}

// ===============================================================
// Test 1: Guard & trivial paths
// ===============================================================
BOOLEAN test_art_delete_guards_and_trivial()
{
    TEST_START("art_delete: guards & trivial");

    reset_mock_state();

#pragma warning(push)
#pragma warning(disable: 6387)
    // 1.1 NULL parameters
    ULONG v = art_delete(NULL, NULL);
#pragma warning(pop)
    TEST_ASSERT(v == POLICY_NONE, "1.1: NULL tree/key -> POLICY_NONE");

    // 1.2 Empty tree (size==0) returns immediately (no conversion)
    ART_TREE t; ad_zero(&t, sizeof(t));
    t.root = NULL; t.size = 0;
    UNICODE_STRING uk = { 0 };
    NTSTATUS st = ad_make_unicode(&uk, L"a", 1);
    TEST_ASSERT(NT_SUCCESS(st), "1-pre: unicode made");
    v = art_delete(&t, &uk);
    TEST_ASSERT(v == POLICY_NONE, "1.2: size==0 -> POLICY_NONE");
    ad_free_unicode(&uk);

    // 1.3 Conversion failure path: give empty UNICODE (unicode_to_utf8 returns NULL)
    // Build non-empty tree so we don't early-return
    UCHAR a = 'a';
    ad_make_single_leaf_tree(&t, &a, 1, 0x11);
    UNICODE_STRING emptyu = { 0 };
    st = ad_make_unicode(&emptyu, L"", 0);
    TEST_ASSERT(NT_SUCCESS(st), "1-pre2: empty unicode");
    v = art_delete(&t, &emptyu);
    TEST_ASSERT(v == POLICY_NONE, "1.3: conversion failure -> POLICY_NONE (no change)");
    // Tree should remain intact
    TEST_ASSERT(t.size == 1, "1.3b: size unchanged on conversion failure");
    ad_free_unicode(&emptyu);
    ad_free_tree(&t.root);

    TEST_END("art_delete: guards & trivial");
    return TRUE;
}

// ===============================================================
// Test 2: Successful delete of single-leaf tree
// ===============================================================
BOOLEAN test_art_delete_single_leaf()
{
    TEST_START("art_delete: single-leaf");

    reset_mock_state();

    ART_TREE t;
    UCHAR a = 'a';
    TEST_ASSERT(ad_make_single_leaf_tree(&t, &a, 1, 0xAB), "2-pre: single leaf tree built");

    UNICODE_STRING uk = { 0 };
    NTSTATUS st = ad_make_unicode(&uk, L"a", 1);
    TEST_ASSERT(NT_SUCCESS(st), "2-pre: unicode 'a'");

    ULONG old = art_delete(&t, &uk);
    TEST_ASSERT(old == 0xAB, "2.1: returns old value");
    TEST_ASSERT(t.size == 0, "2.2: size decremented to 0");
    TEST_ASSERT(t.root == NULL, "2.3: root cleared after delete");

    ad_free_unicode(&uk);
    // nothing to free; root is NULL

    TEST_END("art_delete: single-leaf");
    return TRUE;
}

// ===============================================================
// Test 3: Key not found (non-matching)
// ===============================================================
BOOLEAN test_art_delete_not_found()
{
    TEST_START("art_delete: not found");

    reset_mock_state();

    ART_TREE t;
    TEST_ASSERT(ad_make_node4_two_leaves(&t, 'a', 0x11, 'b', 0x22), "3-pre: node4 with two leaves");

    UNICODE_STRING uk = { 0 };
    NTSTATUS st = ad_make_unicode(&uk, L"c", 1);
    TEST_ASSERT(NT_SUCCESS(st), "3-pre: unicode 'c'");

    ULONG old = art_delete(&t, &uk);
    TEST_ASSERT(old == POLICY_NONE, "3.1: returns POLICY_NONE for missing key");
    TEST_ASSERT(t.size == 2, "3.2: size unchanged");

    // Cleanup
    ad_free_unicode(&uk);
    ad_free_tree(&t.root);

    TEST_END("art_delete: not found");
    return TRUE;
}

// ===============================================================
// Test 4: Delete one of two children (NODE4) – structure remains valid
// ===============================================================
BOOLEAN test_art_delete_one_of_two()
{
    TEST_START("art_delete: delete one among two");

    reset_mock_state();

    ART_TREE t;
    TEST_ASSERT(ad_make_node4_two_leaves(&t, 'a', 0x11, 'b', 0x22), "4-pre: node4 two leaves");

    // Delete 'a'
    UNICODE_STRING uka = { 0 };
    NTSTATUS st = ad_make_unicode(&uka, L"a", 1);
    TEST_ASSERT(NT_SUCCESS(st), "4-pre: unicode 'a'");
    ULONG old = art_delete(&t, &uka);
    TEST_ASSERT(old == 0x11, "4.1: returns old value for 'a'");
    TEST_ASSERT(t.size == 1, "4.2: size decremented by 1");
    TEST_ASSERT(t.root != NULL, "4.3: root still present after one deletion");
    ad_free_unicode(&uka);

    // Now delete 'b' to empty the tree
    UNICODE_STRING ukb = { 0 };
    st = ad_make_unicode(&ukb, L"b", 1);
    TEST_ASSERT(NT_SUCCESS(st), "4-pre2: unicode 'b'");
    old = art_delete(&t, &ukb);
    TEST_ASSERT(old == 0x22, "4.4: returns old value for 'b'");
    TEST_ASSERT(t.size == 0, "4.5: size now 0");
    TEST_ASSERT(t.root == NULL, "4.6: root cleared");
    ad_free_unicode(&ukb);

    TEST_END("art_delete: delete one among two");
    return TRUE;
}

// ===============================================================
// Test 5: Internal node with prefix – exact path deletion
// ===============================================================
BOOLEAN test_art_delete_with_prefix_path()
{
    TEST_START("art_delete: prefixed internal path");

    reset_mock_state();

    ART_TREE t;
    TEST_ASSERT(ad_make_prefixed_node4_one_leaf(&t, 'x', 'y', 0x55), "5-pre: tree {x,y}");

    // Delete full key L"xy"
    WCHAR wkey[3] = { L'x', L'y', L'\0' };
    UNICODE_STRING uk = { 0 };
    NTSTATUS st = ad_make_unicode(&uk, wkey, 2);
    TEST_ASSERT(NT_SUCCESS(st), "5-pre: unicode 'xy'");

    ULONG old = art_delete(&t, &uk);
    TEST_ASSERT(old == 0x55, "5.1: returns old value for 'xy'");
    TEST_ASSERT(t.size == 0, "5.2: size decremented to 0");
    TEST_ASSERT(t.root == NULL, "5.3: root cleared");
    ad_free_unicode(&uk);

    TEST_END("art_delete: prefixed internal path");
    return TRUE;
}

// ===============================================================
// Test 6: Delete same key twice – second call returns POLICY_NONE
// ===============================================================
BOOLEAN test_art_delete_double_delete()
{
    TEST_START("art_delete: double delete");

    reset_mock_state();

    ART_TREE t;
    UCHAR a = 'a';
    TEST_ASSERT(ad_make_single_leaf_tree(&t, &a, 1, 0x7A), "6-pre: single leaf");

    UNICODE_STRING uk = { 0 };
    NTSTATUS st = ad_make_unicode(&uk, L"a", 1);
    TEST_ASSERT(NT_SUCCESS(st), "6-pre: unicode 'a'");

    ULONG v1 = art_delete(&t, &uk);
    TEST_ASSERT(v1 == 0x7A, "6.1: first delete returns value");

    ULONG v2 = art_delete(&t, &uk);
    TEST_ASSERT(v2 == POLICY_NONE, "6.2: second delete returns POLICY_NONE");
    TEST_ASSERT(t.size == 0, "6.3: size remains 0");
    TEST_ASSERT(t.root == NULL, "6.4: root remains NULL");

    ad_free_unicode(&uk);

    TEST_END("art_delete: double delete");
    return TRUE;
}

BOOLEAN test_art_delete_rejects_overlong_key()
{
    TEST_START("art_delete: rejects overlong key (optional)");
#ifndef MAX_KEY_LENGTH
    LOG_MSG("[INFO] MAX_KEY_LENGTH not defined; skipping.\n");
    TEST_END("art_delete: rejects overlong key (optional)");
    return TRUE;
#else
    reset_mock_state();

    ART_TREE t;
    UCHAR a = 'a';
    TEST_ASSERT(ad_make_single_leaf_tree(&t, &a, 1, 0x42), "pre: single-leaf tree");

    // --- Güvenli overlong uzunluk hesapla ---
    // UNICODE_STRING.Length = L * sizeof(WCHAR) → USHORT limitine sığmalı.
    // Ayrıca L > MAX_KEY_LENGTH olmalı ki "overlong" olsun.
    const size_t maxL_by_unicode = (MAXUSHORT / sizeof(WCHAR)) - 1; // terminatör için 1 char bırak
    size_t Lsz = (size_t)MAX_KEY_LENGTH + 1;                        // overlong yap
    if (Lsz > maxL_by_unicode) {
        // Eğer MAX_KEY_LENGTH çok büyükse, yine de overlong kalsın:
        // MAX_KEY_LENGTH == maxL_by_unicode ise Lsz = maxL_by_unicode (eşit) olurdu;
        // bu durumda +1 yapamayız; testin anlamlı olabilmesi için
        // MAX_KEY_LENGTH'i düşürmen gerekir. Burada test'i "skip" edelim.
        LOG_MSG("[INFO] MAX_KEY_LENGTH is too large for UNICODE_STRING; skipping test.\n");
        ad_free_tree(&t.root);
        TEST_END("art_delete: rejects overlong key (optional)");
        return TRUE;
    }

    USHORT L = (USHORT)Lsz; // Artık USHORT içine güvenle sığıyor

    WCHAR* w = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)(L + 1) * sizeof(WCHAR), ART_TAG);
    TEST_ASSERT(w != NULL, "pre: alloc long unicode");
    for (USHORT i = 0; i < L; ++i) w[i] = L'a';
    w[L] = L'\0';

    UNICODE_STRING uk;
    uk.Length = (USHORT)(L * sizeof(WCHAR));
    uk.MaximumLength = (USHORT)((L + 1) * sizeof(WCHAR));
    uk.Buffer = w;

    ULONG old = art_delete(&t, &uk);
    TEST_ASSERT(old == POLICY_NONE, "overlong key -> POLICY_NONE");
    TEST_ASSERT(t.size == 1 && t.root != NULL, "tree unchanged");

    ExFreePool2(w, ART_TAG, NULL, 0);
    ad_free_tree(&t.root);

    TEST_END("art_delete: rejects overlong key (optional)");
    return TRUE;
#endif
}


// ===============================================================
// Suite runner
// ===============================================================
NTSTATUS run_all_art_delete_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_delete() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_art_delete_guards_and_trivial()) all = FALSE;   // (1) guards, empty tree, conversion failure
    if (!test_art_delete_single_leaf())        all = FALSE;   // (2) single-leaf success
    if (!test_art_delete_not_found())          all = FALSE;   // (3) not found
    if (!test_art_delete_one_of_two())         all = FALSE;   // (4) remove one of two children
    if (!test_art_delete_with_prefix_path())   all = FALSE;   // (5) internal prefix traversal
    if (!test_art_delete_double_delete())      all = FALSE;   // (6) idempotence
    if (!test_art_delete_rejects_overlong_key())      all = FALSE;   // (6) idempotence


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL art_delete() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_delete() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
