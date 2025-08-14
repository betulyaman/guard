#if UNIT_TEST

#include "test_art.h"

// Function under test
NTSTATUS art_insert(_Inout_ ART_TREE* tree,
    _In_ PCUNICODE_STRING unicode_key,
    _In_ ULONG value,
    _Out_opt_ PULONG old_value);

// ---------- local helpers (no CRT) ----------
static VOID t_fill_ascii_w(WCHAR* dst, USHORT chars, WCHAR ch) {
    for (USHORT i = 0; i < chars; i++) dst[i] = ch;
}
static SIZE_T t_memcmp(const VOID* a, const VOID* b, SIZE_T n) {
    return RtlCompareMemory(a, b, n);
}

// ========================= Test 1: Guard checks =========================
BOOLEAN test_art_insert_guards()
{
    TEST_START("art_insert: guard checks");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us;
    WCHAR wbuf[] = L"x";
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 1)), "1-pre: make unicode");

    NTSTATUS st;

    st = art_insert(NULL, &us, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL tree rejected");

    st = art_insert(&tree, NULL, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL unicode_key rejected");

    // zero-length key
    UNICODE_STRING zero;
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&zero, L"", 0)), "1-pre: make zero len");
    zero.Length = 0;
    st = art_insert(&tree, &zero, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: empty key rejected");

    cleanup_unicode_string(&zero);
    cleanup_unicode_string(&us);

    TEST_END("art_insert: guard checks");
    return TRUE;
}

// ========================= Test 2: Conversion failure (unicode_to_utf8 returns NULL) =========================
BOOLEAN test_art_insert_conversion_failure()
{
    TEST_START("art_insert: unicode_to_utf8 failure path");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING bad;
    bad.Length = 2;           // pretend non-zero length
    bad.MaximumLength = 2;
    bad.Buffer = NULL;        // ensures unicode_to_utf8 fails early

    ULONG frees_before = g_free_call_count;
    NTSTATUS st = art_insert(&tree, &bad, 123, NULL);

    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "2.1: conversion failure , INSUFFICIENT_RESOURCES");
    TEST_ASSERT(tree.size == 0, "2.2: size remains 0");
    TEST_ASSERT(g_free_call_count == frees_before, "2.3: no temp free since key was never allocated");

    TEST_END("art_insert: unicode_to_utf8 failure path");
    return TRUE;
}

// ========================= Test 3: Insert into empty tree , new leaf, size++ =========================
BOOLEAN test_art_insert_empty_tree_creates_leaf_and_increments_size()
{
    TEST_START("art_insert: empty , creates leaf, size++");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "3-pre: init tree");

    // key = L"Ab" (lowercased by unicode_to_utf8)
    UNICODE_STRING us;
    WCHAR wbuf[2] = { L'A', L'b' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 2)), "3-pre: make unicode");

    ULONG frees_before = g_free_call_count;
    NTSTATUS st = art_insert(&tree, &us, /*value*/42, /*old_value*/NULL);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: insert succeeds");
    TEST_ASSERT(tree.size == 1, "3.2: size incremented to 1");
    TEST_ASSERT(tree.root != NULL, "3.3: root set");
    TEST_ASSERT(IS_LEAF(tree.root), "3.4: root is a leaf");

    // temp key freed
    TEST_ASSERT(g_free_call_count >= frees_before + 1, "3.5: temp UTF-8 key freed (>=+1 frees)");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "3.6: correct tag used for free");

    // validate leaf content
    ART_LEAF* lf = LEAF_RAW(tree.root);
    TEST_ASSERT(lf != NULL, "3.7: leaf non-NULL");
    TEST_ASSERT(lf->value == 42, "3.8: value stored");

    // key should be "ab" (lowercased)
    UCHAR expect[2] = { 'a','b' };
    TEST_ASSERT(lf->key_length == 2, "3.9: key_length=2");
    TEST_ASSERT(t_memcmp(lf->key, expect, 2) == 2, "3.10: key bytes match");

    // cleanup
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert: empty , creates leaf, size++");
    return TRUE;
}

// ========================= Test 4: Duplicate keyreplace, size steady, old_value set =========================
BOOLEAN test_art_insert_duplicate_key_replaces_and_reports_old_value()
{
    TEST_START("art_insert: duplicate key , replace, old_value, size steady");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    // first insert
    UNICODE_STRING us;
    WCHAR wbuf[3] = { L'X', L'Y', L'Z' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 3)), "4-pre: make unicode");

    NTSTATUS st = art_insert(&tree, &us, /*value*/100, /*old*/NULL);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: first insert ok");
    TEST_ASSERT(tree.size == 1, "4.2: size=1");

    // second insert same key, different value, capture old_value
    ULONG oldv = 0xFFFFFFFF;
    st = art_insert(&tree, &us, /*value*/555, /*old*/&oldv);
    TEST_ASSERT(NT_SUCCESS(st), "4.3: second insert ok");
    TEST_ASSERT(tree.size == 1, "4.4: size unchanged for duplicate");
    TEST_ASSERT(oldv == 100, "4.5: old_value returned");

    // confirm leaf value updated
    TEST_ASSERT(IS_LEAF(tree.root), "4.6: still leaf at root");
    ART_LEAF* lf = LEAF_RAW(tree.root);
    TEST_ASSERT(lf && lf->value == 555, "4.7: value replaced to 555");

    // cleanup
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert: duplicate key , replace, old_value, size steady");
    return TRUE;
}

// ========================= Test 5: Two distinct keyssize=2 =========================
BOOLEAN test_art_insert_two_distinct_keys_size_two()
{
    TEST_START("art_insert: two distinct keys , size=2");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us1, us2;
    WCHAR k1[3] = { L'a', L'a', L'1' };
    WCHAR k2[3] = { L'a', L'a', L'2' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us1, k1, 3)), "5-pre: us1");
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us2, k2, 3)), "5-pre: us2");

    NTSTATUS st = art_insert(&tree, &us1, 11, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: insert #1 ok");
    TEST_ASSERT(tree.size == 1, "5.2: size=1");

    st = art_insert(&tree, &us2, 22, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "5.3: insert #2 ok");
    TEST_ASSERT(tree.size == 2, "5.4: size=2");

    TEST_ASSERT(tree.root != NULL, "5.5: root exists");

    // cleanup (free shallow)
    if (IS_LEAF(tree.root)) {
        ART_LEAF* lf = LEAF_RAW(tree.root);
        free_leaf(&lf);
    }
    else {
        ART_NODE4* n4 = (ART_NODE4*)tree.root;
        for (USHORT i = 0; i < n4->base.num_of_child; i++) {
            ART_NODE* c = n4->children[i];
            if (IS_LEAF(c)) {
                ART_LEAF* lf = LEAF_RAW(c);
                free_leaf(&lf);
                n4->children[i] = NULL;
            }
        }
        ExFreePool2(n4, ART_TAG, NULL, 0);
    }
    tree.root = NULL;

    cleanup_unicode_string(&us1);
    cleanup_unicode_string(&us2);

    TEST_END("art_insert: two distinct keys , size=2");
    return TRUE;
}

// ========================= Test 6: Temp UTF-8 key freed on success =========================
BOOLEAN test_art_insert_temp_key_freed_on_success()
{
    TEST_START("art_insert: temp UTF-8 key freed (success path)");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us;
    WCHAR wbuf[2] = { L'H', L'i' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 2)), "6-pre: unicode");

    ULONG free_before = g_free_call_count;
    NTSTATUS st = art_insert(&tree, &us, 9, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: insert ok");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "6.2: temp UTF-8 key freed (>=+1 frees)");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "6.3: freed with ART_TAG");

    // cleanup
    if (IS_LEAF(tree.root)) {
        ART_LEAF* lf = LEAF_RAW(tree.root);
        free_leaf(&lf);
    }
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert: temp UTF-8 key freed (success path)");
    return TRUE;
}

// ========================= Test 7: Conversion failure (Buffer==NULL)no temp free =========================
BOOLEAN test_art_insert_no_free_when_conversion_fails()
{
    TEST_START("art_insert: conversion fails , no temp free");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING bad;
    bad.Length = 4;
    bad.MaximumLength = 4;
    bad.Buffer = NULL;

    ULONG free_before = g_free_call_count;
    NTSTATUS st = art_insert(&tree, &bad, 1, NULL);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "7.1: conversion failure status");
    TEST_ASSERT(g_free_call_count == free_before, "7.2: no free of temp key since none allocated");

    TEST_END("art_insert: conversion fails , no temp free");
    return TRUE;
}

// ========================= Test 8: Key too long after UTF-8rejected & temp key freed =========================
BOOLEAN test_art_insert_key_too_long_rejected_and_temp_freed()
{
    TEST_START("art_insert: key too long rejects and frees temp key");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "8-pre: init tree");

    // Build a Unicode key that will become UTF-8 length > MAX_KEY_LENGTH
    USHORT chars = (USHORT)(MAX_KEY_LENGTH + 1); // each 'a'1 byte in UTF-8
    SIZE_T bytes = (SIZE_T)chars * sizeof(WCHAR);
    WCHAR* wbuf = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, ART_TAG);
    TEST_ASSERT(wbuf != NULL, "8-pre: alloc wbuf");
    t_fill_ascii_w(wbuf, chars, L'a');

    UNICODE_STRING us;
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, chars)), "8-pre: make unicode");

    ULONG free_before = g_free_call_count;
    NTSTATUS st = art_insert(&tree, &us, 77, NULL);

    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "8.1: too-long key must be rejected");
    TEST_ASSERT(tree.size == 0, "8.2: size unchanged");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "8.3: temp UTF-8 key freed on too-long path");

    cleanup_unicode_string(&us);
    ExFreePool2(wbuf, ART_TAG, NULL, 0);

    TEST_END("art_insert: key too long rejects and frees temp key");
    return TRUE;
}

// ========================= Test X: Overflow rollback (size == MAXULONG) =========================
BOOLEAN test_art_insert_overflow_rollback_new_key()
{
    TEST_START("art_insert: overflow rollback for new key");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "X-pre: init tree");
    tree.size = MAXULONG;

    UNICODE_STRING us;
    WCHAR wbuf[2] = { L'z', L'z' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 2)), "X-pre: make unicode key");

    ULONG free_before = g_free_call_count;

    NTSTATUS st = art_insert(&tree, &us, /*value*/1234, /*old_value*/NULL);

    TEST_ASSERT(st == STATUS_INTEGER_OVERFLOW, "X.1: must return STATUS_INTEGER_OVERFLOW");
    TEST_ASSERT(tree.root == NULL, "X.2: root must remain NULL (rolled back to empty)");
    TEST_ASSERT(tree.size == MAXULONG, "X.3: size must remain MAXULONG (no increment)");
    TEST_ASSERT(g_free_call_count >= free_before + 2, "X.4: frees include temp key and removed leaf");

    cleanup_unicode_string(&us);

    TEST_END("art_insert: overflow rollback for new key");
    return TRUE;
}

// ========================= Suite Runner =========================
NTSTATUS run_all_art_insert_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_insert() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_art_insert_guards())                                  all = FALSE; // 1
    if (!test_art_insert_conversion_failure())                       all = FALSE; // 2
    if (!test_art_insert_empty_tree_creates_leaf_and_increments_size()) all = FALSE; // 3
    if (!test_art_insert_duplicate_key_replaces_and_reports_old_value()) all = FALSE; // 4
    if (!test_art_insert_two_distinct_keys_size_two())               all = FALSE; // 5
    if (!test_art_insert_temp_key_freed_on_success())                all = FALSE; // 6
    if (!test_art_insert_no_free_when_conversion_fails())            all = FALSE; // 7
    if (!test_art_insert_key_too_long_rejected_and_temp_freed())     all = FALSE; // 8 (new)
    if (!test_art_insert_overflow_rollback_new_key())                all = FALSE; // X

    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL art_insert() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_insert() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif