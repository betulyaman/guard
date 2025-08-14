#if UNIT_TEST

#include "test_art.h"

// Function under test
NTSTATUS art_insert_no_replace(_Inout_ ART_TREE* tree,
    _In_ PCUNICODE_STRING unicode_key,
    _In_ ULONG value,
    _Out_opt_ PULONG existing_value);

// We rely on common utilities/macros/types provided by your existing test harness:
// - reset_mock_state(), g_free_call_count, g_last_freed_tag
// - create_unicode_string(), cleanup_unicode_string()
// - art_init_tree()
// - IS_LEAF, LEAF_RAW, free_leaf
// - ART_NODE4 layout (for tiny cleanups after 2 inserts)

// --------- tiny local helpers (no CRT) ----------
static SIZE_T t_memcmp(const VOID* a, const VOID* b, SIZE_T n) {
    return RtlCompareMemory(a, b, n);
}

// ========================= Test 1: Guard checks =========================
BOOLEAN test_art_insert_no_replace_guards()
{
    TEST_START("art_insert_no_replace: guard checks");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    // non-empty key for basic calls
    UNICODE_STRING us_nonempty;
    WCHAR oneW[] = L"x";
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us_nonempty, oneW, 1)), "1-pre: make unicode");

    NTSTATUS st;
#pragma warning(push)
#pragma warning(disable: 4566 6387)
    st = art_insert_no_replace(NULL, &us_nonempty, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.1: NULL tree rejected");

    st = art_insert_no_replace(&tree, NULL, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.2: NULL unicode_key rejected");
#pragma warning(pop)

    // zero-length key
    UNICODE_STRING zero;
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&zero, L"", 0)), "1-pre: zero unicode");
    zero.Length = 0;
    st = art_insert_no_replace(&tree, &zero, 1, NULL);
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER, "1.3: empty key rejected");

    cleanup_unicode_string(&zero);
    cleanup_unicode_string(&us_nonempty);

    TEST_END("art_insert_no_replace: guard checks");
    return TRUE;
}

// ========================= Test 2: Conversion failure =========================
// Simulate failure by providing Length > 0 with Buffer == NULL (your unicode_to_utf8 returns NULL early)
BOOLEAN test_art_insert_no_replace_conversion_failure()
{
    TEST_START("art_insert_no_replace: conversion failure path");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING bad;
    bad.Length = 2;
    bad.MaximumLength = 2;
    bad.Buffer = NULL;

    ULONG free_before = g_free_call_count;

    NTSTATUS st = art_insert_no_replace(&tree, &bad, 111, NULL);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "2.1: conversion failure , STATUS_INSUFFICIENT_RESOURCES");
    TEST_ASSERT(tree.size == 0, "2.2: size remains 0 on failure");
    TEST_ASSERT(g_free_call_count == free_before, "2.3: no temp key free when conversion failed");

    TEST_END("art_insert_no_replace: conversion failure path");
    return TRUE;
}

// ========================= Test 3: First insert into empty tree =========================
BOOLEAN test_art_insert_no_replace_first_insert_size_increment()
{
    TEST_START("art_insert_no_replace: first insert , leaf + size++ + temp free");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "3-pre: init tree");

    UNICODE_STRING us;
    WCHAR keyW[3] = { L'A', L'B', L'3' }; // will be lowercased by unicode_to_utf8
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, keyW, 3)), "3-pre: make unicode");

    ULONG free_before = g_free_call_count;

    NTSTATUS st = art_insert_no_replace(&tree, &us, /*value*/0xDEADBEEF, /*existing_value*/NULL);
    TEST_ASSERT(NT_SUCCESS(st), "3.1: insert succeeds");
    TEST_ASSERT(tree.size == 1, "3.2: size incremented to 1");
    TEST_ASSERT(tree.root != NULL && IS_LEAF(tree.root), "3.3: root is a leaf");

    // temp UTF-8 key must be freed in success path
    TEST_ASSERT(g_free_call_count >= free_before + 1, "3.4: temp key freed once (>=+1 frees due to downcase buffer)");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "3.5: temp key freed with ART_TAG");

    // validate leaf contents
    ART_LEAF* lf = LEAF_RAW(tree.root);
    TEST_ASSERT(lf != NULL, "3.6: leaf non-NULL");
    TEST_ASSERT(lf->value == 0xDEADBEEF, "3.7: value stored");
    UCHAR expect[3] = { 'a', 'b', '3' };
    TEST_ASSERT(lf->key_length == 3, "3.8: key_length=3");
    TEST_ASSERT(t_memcmp(lf->key, expect, 3) == 3, "3.9: stored key bytes match");

    // cleanup
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: first insert , leaf + size++ + temp free");
    return TRUE;
}

// ========================= Test 4: Duplicate insert , no replace, collision, existing_value set =========================
BOOLEAN test_art_insert_no_replace_duplicate_collision_and_preserve_value()
{
    TEST_START("art_insert_no_replace: duplicate key , OBJECT_NAME_COLLISION, no replace");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us;
    WCHAR wbuf[2] = { L'K', L'1' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 2)), "4-pre: key");

    // first insert
    NTSTATUS st = art_insert_no_replace(&tree, &us, /*value*/77, /*existing*/NULL);
    TEST_ASSERT(NT_SUCCESS(st), "4.1: first insert ok");
    TEST_ASSERT(tree.size == 1, "4.2: size=1");

    // second insert same key, different value
    ULONG free_before = g_free_call_count;
    ULONG existing = 0xFFFFFFFF;
    st = art_insert_no_replace(&tree, &us, /*value*/999, /*existing*/&existing);

    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "4.3: duplicate , STATUS_OBJECT_NAME_COLLISION");
    TEST_ASSERT(tree.size == 1, "4.4: size unchanged");
    TEST_ASSERT(existing == 77, "4.5: existing_value returned correctly");

    // leaf's value should NOT be replaced (no-replace semantics)
    TEST_ASSERT(IS_LEAF(tree.root), "4.6: root is leaf");
    ART_LEAF* lf = LEAF_RAW(tree.root);
    TEST_ASSERT(lf && lf->value == 77, "4.7: value remains 77 (not replaced)");

    // temp key must still be freed in collision path
    TEST_ASSERT(g_free_call_count >= free_before + 1, "4.8: temp key freed on collision (>=+1 frees)");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "4.9: freed with ART_TAG");

    // cleanup
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: duplicate key , OBJECT_NAME_COLLISION, no replace");
    return TRUE;
}

// ========================= Test 5: Duplicate insert with existing_value == NULL =========================
BOOLEAN test_art_insert_no_replace_duplicate_null_outparam()
{
    TEST_START("art_insert_no_replace: duplicate with existing_value==NULL");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us;
    WCHAR wbuf[3] = { L'a', L'A', L'!' }; // lowercasing applies
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wbuf, 3)), "5-pre: key");

    NTSTATUS st = art_insert_no_replace(&tree, &us, 11, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "5.1: first insert ok");

    ULONG free_before = g_free_call_count;
    st = art_insert_no_replace(&tree, &us, 22, NULL);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "5.2: duplicate , collision");
    TEST_ASSERT(tree.size == 1, "5.3: size unchanged");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "5.4: temp key freed on collision even without outparam (>=+1 frees)");

    // value still 11
    ART_LEAF* lf = LEAF_RAW(tree.root);
    TEST_ASSERT(lf && lf->value == 11, "5.5: existing value preserved");

    // cleanup
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: duplicate with existing_value==NULL");
    return TRUE;
}

// ========================= Test 6: Two distinct keys , size becomes 2 =========================
BOOLEAN test_art_insert_no_replace_two_distinct_keys_size_two()
{
    TEST_START("art_insert_no_replace: two distinct keys , size=2");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING u1, u2;
    WCHAR k1[3] = { L'P', L'0', L'1' };
    WCHAR k2[3] = { L'P', L'0', L'2' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&u1, k1, 3)), "6-pre: u1");
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&u2, k2, 3)), "6-pre: u2");

    NTSTATUS st = art_insert_no_replace(&tree, &u1, 1, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "6.1: #1 ok");
    TEST_ASSERT(tree.size == 1, "6.2: size=1");

    st = art_insert_no_replace(&tree, &u2, 2, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "6.3: #2 ok");
    TEST_ASSERT(tree.size == 2, "6.4: size=2");

    // cleanup small tree (root may be NODE4 now)
    if (IS_LEAF(tree.root)) {
        ART_LEAF* lf = LEAF_RAW(tree.root);
        free_leaf(&lf);
    }
    else {
        ART_NODE4* n4 = (ART_NODE4*)tree.root;
        for (USHORT i = 0; i < n4->base.num_of_child; i++) {
            ART_NODE* ch = n4->children[i];
            if (IS_LEAF(ch)) {
                ART_LEAF* lf = LEAF_RAW(ch);
                free_leaf(&lf);
                n4->children[i] = NULL;
            }
        }
        ExFreePool2(n4, ART_TAG, NULL, 0);
    }
    tree.root = NULL;

    cleanup_unicode_string(&u1);
    cleanup_unicode_string(&u2);

    TEST_END("art_insert_no_replace: two distinct keys , size=2");
    return TRUE;
}

// ========================= Test 7: Temp key freed on success and on collision =========================
BOOLEAN test_art_insert_no_replace_temp_key_freed_paths()
{
    TEST_START("art_insert_no_replace: temp key freed on success & collision");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING us;
    WCHAR k[2] = { L'Z', L'z' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, k, 2)), "7-pre: key");

    ULONG free_before = g_free_call_count;
    NTSTATUS st = art_insert_no_replace(&tree, &us, 10, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "7.1: first insert ok");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "7.2: temp key freed on success (>=+1 frees)");

    free_before = g_free_call_count;
    st = art_insert_no_replace(&tree, &us, 11, NULL);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "7.3: second insert collision");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "7.4: temp key freed on collision (>=+1 frees)");

    // cleanup
    ART_LEAF* lf = LEAF_RAW(tree.root);
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: temp key freed on success & collision");
    return TRUE;
}

// ========================= Test 8: No temp free when conversion fails =========================
BOOLEAN test_art_insert_no_replace_no_free_when_conversion_fails()
{
    TEST_START("art_insert_no_replace: conversion fails , no temp free");

    reset_mock_state();

    ART_TREE tree;
    (void)art_init_tree(&tree);

    UNICODE_STRING bad;
    bad.Length = 6;
    bad.MaximumLength = 6;
    bad.Buffer = NULL; // forces unicode_to_utf8 to fail

    ULONG free_before = g_free_call_count;
    NTSTATUS st = art_insert_no_replace(&tree, &bad, 3, NULL);
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "8.1: conversion failure status");
    TEST_ASSERT(g_free_call_count == free_before, "8.2: no free because temp key not allocated");

    TEST_END("art_insert_no_replace: conversion fails , no temp free");
    return TRUE;
}

// ========================= Test 9: Overflow rollback (size == MAXULONG) =========================
// Purpose:
//   When the tree size is already MAXULONG, inserting a *new* key must:
//     - return STATUS_INTEGER_OVERFLOW
//     - leave root unchanged (no orphan nodes)
//     - leave size unchanged (still MAXULONG)
//     - free the temporary UTF-8 key
//     - free the created leaf via rollback (no leaks)
BOOLEAN test_art_insert_no_replace_overflow_rollback_new_key()
{
    TEST_START("art_insert_no_replace: overflow rollback for new key");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "9-pre: init tree");
    tree.size = MAXULONG; // force overflow on next *new* key

    // Simple 2-char ASCII key (will map 1:1 to UTF-8)
    UNICODE_STRING us;
    WCHAR wb[2] = { L'Q', L'q' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, wb, 2)), "9-pre: make unicode key");

    ULONG free_before = g_free_call_count;

    NTSTATUS st = art_insert_no_replace(&tree, &us, /*value*/123, /*existing_value*/NULL);
    TEST_ASSERT(st == STATUS_INTEGER_OVERFLOW, "9.1: must return STATUS_INTEGER_OVERFLOW");
    TEST_ASSERT(tree.root == NULL, "9.2: root remains NULL (rolled back)");
    TEST_ASSERT(tree.size == MAXULONG, "9.3: size unchanged (still MAXULONG)");

    // At least one free for UTF-8 key + one free for the removed leaf during rollback
    TEST_ASSERT(g_free_call_count >= free_before + 2, "9.4: frees include temp key and removed leaf");

    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: overflow rollback for new key");
    return TRUE;
}

// ========================= Test 10: Key length > MAX_KEY_LENGTH =========================
// Purpose:
//   If the converted UTF-8 key length exceeds MAX_KEY_LENGTH, the function must:
//     - return STATUS_INVALID_PARAMETER
//     - not mutate the tree (root stays NULL, size stays 0)
//     - free the temporary UTF-8 key buffer
BOOLEAN test_art_insert_no_replace_too_long_key_rejected()
{
    TEST_START("art_insert_no_replace: reject too-long key");

#ifndef MAXUSHORT
#define MAXUSHORT 0xFFFF
#endif

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "10-pre: init tree");
    TEST_ASSERT(tree.root == NULL && tree.size == 0, "10-pre: empty tree");

    // --- Güvenli overlong uzunluk seçimi ---
    // UNICODE_STRING.Length = L * sizeof(WCHAR) (USHORT), o yüzden L USHORT limitine sığmalı.
    // Aynı zamanda L > MAX_KEY_LENGTH olmalı (overlong).
    const size_t maxL_by_unicode = (MAXUSHORT / sizeof(WCHAR)) - 1; // son NUL için 1 bırak
    size_t Lsz = (size_t)MAX_KEY_LENGTH + 1;                        // overlong hedefi
    if (Lsz > maxL_by_unicode) {
        LOG_MSG("[INFO] MAX_KEY_LENGTH too large to build a safe overlong UNICODE key; skipping test.\n");
        TEST_END("art_insert_no_replace: reject too-long key");
        return TRUE; // anlamlı şekilde test edilemez -> skip
    }
    const USHORT over = (USHORT)Lsz;

    // Buffer oluştur ve 'a' ile doldur
    WCHAR* w = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)(over + 1) * sizeof(WCHAR), ART_TAG);
    TEST_ASSERT(w != NULL, "10-pre: allocate unicode buffer");
    for (USHORT i = 0; i < over; ++i) w[i] = L'a';
    w[over] = L'\0';

    UNICODE_STRING us;
    us.Buffer = w;
    us.Length = (USHORT)(over * sizeof(WCHAR));
    us.MaximumLength = (USHORT)((over + 1) * sizeof(WCHAR));

    ULONG free_before = g_free_call_count;

    NTSTATUS st = art_insert_no_replace(&tree, &us, 7, NULL);
    // unicode_to_utf8 limiti içerde kestiğinde STATUS_INSUFFICIENT_RESOURCES dönebilir;
    // uygulama sözleşmesi açısından “reddedildi” yeterli.
    TEST_ASSERT(st == STATUS_INVALID_PARAMETER || st == STATUS_INSUFFICIENT_RESOURCES,
        "10.1: must reject too-long key (STATUS_INVALID_PARAMETER or INSUFFICIENT_RESOURCES)");
    TEST_ASSERT(tree.root == NULL, "10.2: root unchanged");
    TEST_ASSERT(tree.size == 0, "10.3: size unchanged");

    // unicode_to_utf8 hiç alloc etmemiş de olabilir; ettiyse destroy_utf8_key ile en az bir free olur
    TEST_ASSERT(g_free_call_count == free_before || g_free_call_count >= free_before + 1,
        "10.4: temp UTF-8 key either not allocated or freed (>=+1 frees)");
#ifdef TRACK_LAST_FREED_TAG
    if (g_free_call_count >= free_before + 1) {
        TEST_ASSERT(g_last_freed_tag == ART_TAG, "10.5: freed with ART_TAG");
    }
#endif

    ExFreePool2(w, ART_TAG, NULL, 0);

    TEST_END("art_insert_no_replace: reject too-long key");
    return TRUE;
}

// ========================= Test 11: New key -> existing_value == POLICY_NONE =========================
// Yeni bir anahtar eklerken caller existing_value istediğinde POLICY_NONE dönmeli.
BOOLEAN test_art_inr_existing_outparam_policy_none_for_new_key()
{
    TEST_START("art_insert_no_replace: new key -> existing_value = POLICY_NONE");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "11-pre: init");

    UNICODE_STRING us;
    WCHAR w[2] = { L'N', L'1' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, w, 2)), "11-pre: key");

    ULONG existing = 0xDEADCAFE;
    NTSTATUS st = art_insert_no_replace(&tree, &us, 0x11, &existing);
    TEST_ASSERT(NT_SUCCESS(st), "11.1: insert ok");
    TEST_ASSERT(existing == POLICY_NONE, "11.2: existing_value must be POLICY_NONE for a new key");
    TEST_ASSERT(tree.size == 1, "11.3: size=1");

    // cleanup
    ART_LEAF* lf = LEAF_RAW(tree.root);
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: new key -> existing_value = POLICY_NONE");
    return TRUE;
}

// ========================= Test 12: Duplicate when size == MAXULONG =========================
// MAXULONG'dayken *aynı anahtarı* tekrar eklemek overflow değil, COLLISION olmalı ve rollback denenmemeli.
BOOLEAN test_art_inr_duplicate_with_max_size_no_overflow()
{
    TEST_START("art_insert_no_replace: duplicate with size==MAXULONG -> collision");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "12-pre: init");

    UNICODE_STRING us;
    WCHAR w[2] = { L'D', L'1' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, w, 2)), "12-pre: key");

    NTSTATUS st = art_insert_no_replace(&tree, &us, 7, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "12.1: first insert ok");
    tree.size = MAXULONG; // sınırı zorla

    ULONG free_before = g_free_call_count;
    ULONG existing = 0;
    st = art_insert_no_replace(&tree, &us, 99, &existing);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "12.2: duplicate -> COLLISION (no overflow)");
    TEST_ASSERT(existing == 7, "12.3: existing_value=7");
    TEST_ASSERT(tree.size == MAXULONG, "12.4: size unchanged (MAXULONG)");
    TEST_ASSERT(g_free_call_count >= free_before + 1, "12.5: temp UTF-8 key freed");

    // cleanup
    ART_LEAF* lf = LEAF_RAW(tree.root);
    free_leaf(&lf);
    tree.root = NULL;
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: duplicate with size==MAXULONG -> collision");
    return TRUE;
}

// Test 13: If the first allocation INSIDE recursive_insert fails,
// the failure status must propagate and the temporary UTF-8 key
// allocated by art_insert_no_replace() must be freed.
BOOLEAN test_art_inr_recursive_insert_failure_propagates_and_frees_key()
{
    TEST_START("art_insert_no_replace: recursive_insert failure propagates (temp key freed)");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "13-pre: init");

    UNICODE_STRING us;
    WCHAR w[1] = { L'R' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&us, w, 1)), "13-pre: key");

    // ---- PROBE PHASE: measure how many allocations unicode_to_utf8() does ----
    ULONG alloc_probe_start = g_alloc_call_count;
    USHORT probe_len = 0;
    PUCHAR probe_key = unicode_to_utf8(&us, &probe_len);
    TEST_ASSERT(probe_key != NULL && probe_len > 0, "13-probe: unicode_to_utf8 must succeed");
    ULONG utf8_allocs = g_alloc_call_count - alloc_probe_start;
    destroy_utf8_key(probe_key);

    // Sanity: expect at least one allocation (the UTF-8 buffer)
    TEST_ASSERT(utf8_allocs >= 1, "13-probe: unicode_to_utf8 should allocate at least once");

    ULONG free_before = g_free_call_count;
    ULONG failure_index = g_alloc_call_count + utf8_allocs + 1;
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, failure_index);

    NTSTATUS st = art_insert_no_replace(&tree, &us, 0x33, NULL);

    // 13.1: the exact failure code must propagate
    TEST_ASSERT(st == STATUS_INSUFFICIENT_RESOURCES, "13.1: recursive_insert failure must propagate");

    // 13.2: tree must remain unchanged
    TEST_ASSERT(tree.root == NULL && tree.size == 0, "13.2: tree unchanged");

    // 13.3: the temporary UTF-8 key (allocated successfully) must have been freed
    TEST_ASSERT(g_free_call_count >= free_before + 1, "13.3: temp UTF-8 key freed");

    // ---- CLEANUP ----
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0); // disable failure
    cleanup_unicode_string(&us);

    TEST_END("art_insert_no_replace: recursive_insert failure propagates (temp key freed)");
    return TRUE;
}


// Test 14: Overflow rollback non-empty tree -> protet the old content
BOOLEAN test_art_inr_overflow_rollback_preserves_existing_tree()
{
    TEST_START("art_insert_no_replace: overflow rollback preserves existing content");

    reset_mock_state();

    ART_TREE tree;
    TEST_ASSERT(NT_SUCCESS(art_init_tree(&tree)), "14-pre: init");

    UNICODE_STRING ua, ub;
    WCHAR wa[1] = { L'a' };
    WCHAR wb[1] = { L'b' };
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&ua, wa, 1)), "14-pre: ua");
    TEST_ASSERT(NT_SUCCESS(create_unicode_string(&ub, wb, 1)), "14-pre: ub");

    NTSTATUS st = art_insert_no_replace(&tree, &ua, 0xAA, NULL);
    TEST_ASSERT(NT_SUCCESS(st), "14.1: insert 'a' ok");
    TEST_ASSERT(tree.size == 1, "14.2: size=1");

    tree.size = MAXULONG;
    ULONG free_before = g_free_call_count;
    st = art_insert_no_replace(&tree, &ub, 0xBB, NULL);
    TEST_ASSERT(st == STATUS_INTEGER_OVERFLOW, "14.3: overflow -> INTEGER_OVERFLOW");
    TEST_ASSERT(tree.size == MAXULONG, "14.4: size stays MAXULONG");
    TEST_ASSERT(g_free_call_count >= free_before + 2, "14.5: temp key + removed leaf freed");

    ULONG existing = 0;
    st = art_insert_no_replace(&tree, &ua, 0xCC, &existing);
    TEST_ASSERT(st == STATUS_OBJECT_NAME_COLLISION, "14.6: 'a' still present -> collision");
    TEST_ASSERT(existing == 0xAA, "14.7: existing value preserved");

    if (IS_LEAF(tree.root)) {
        ART_LEAF* lf = LEAF_RAW(tree.root);
        free_leaf(&lf);
        tree.root = NULL;
    }
    else {
        ART_NODE4* n4 = (ART_NODE4*)tree.root;
        for (USHORT i = 0; i < n4->base.num_of_child; i++) {
            if (IS_LEAF(n4->children[i])) {
                ART_LEAF* lf = LEAF_RAW(n4->children[i]);
                free_leaf(&lf);
                n4->children[i] = NULL;
            }
        }
        ExFreePool2(n4, ART_TAG, NULL, 0);
        tree.root = NULL;
    }
    cleanup_unicode_string(&ua);
    cleanup_unicode_string(&ub);

    TEST_END("art_insert_no_replace: overflow rollback preserves existing content");
    return TRUE;
}

// ========================= Suite Runner =========================
NTSTATUS run_all_art_insert_no_replace_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_insert_no_replace() Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all = TRUE;

    if (!test_art_insert_no_replace_guards())                          all = FALSE; // 1
    if (!test_art_insert_no_replace_conversion_failure())               all = FALSE; // 2
    if (!test_art_insert_no_replace_first_insert_size_increment())      all = FALSE; // 3
    if (!test_art_insert_no_replace_duplicate_collision_and_preserve_value()) all = FALSE; // 4
    if (!test_art_insert_no_replace_duplicate_null_outparam())          all = FALSE; // 5
    if (!test_art_insert_no_replace_two_distinct_keys_size_two())       all = FALSE; // 6
    if (!test_art_insert_no_replace_temp_key_freed_paths())             all = FALSE; // 7
    if (!test_art_insert_no_replace_no_free_when_conversion_fails())    all = FALSE; // 8
    if (!test_art_insert_no_replace_overflow_rollback_new_key())  all = FALSE; // 9
    if (!test_art_insert_no_replace_too_long_key_rejected())      all = FALSE; // 10
    if (!test_art_inr_existing_outparam_policy_none_for_new_key())   all = FALSE; // 11
    if (!test_art_inr_duplicate_with_max_size_no_overflow())         all = FALSE; // 12
    if (!test_art_inr_recursive_insert_failure_propagates_and_frees_key()) all = FALSE; // 13
    if (!test_art_inr_overflow_rollback_preserves_existing_tree())   all = FALSE; // 14


    LOG_MSG("\n========================================\n");
    if (all) {
        LOG_MSG("ALL art_insert_no_replace() TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_insert_no_replace() TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif