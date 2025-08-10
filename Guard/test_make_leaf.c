#include "test_art.h"

// Function under test
STATIC ART_LEAF* make_leaf(CONST PUCHAR key, USHORT key_length, ULONG value);

// -----------------------------
// Tiny helpers
// -----------------------------

static __forceinline USHORT over_keylen(void) {
#if defined(MAX_KEY_LENGTH)
    // If MAX_KEY_LENGTH fits in USHORT, use MAX_KEY_LENGTH+1; otherwise clamp to USHRT_MAX.
    return (USHORT)((MAX_KEY_LENGTH < USHRT_MAX) ? (MAX_KEY_LENGTH + 1U) : USHRT_MAX);
#else
    // If MAX_KEY_LENGTH isn't defined, just use the largest USHORT so the guard path triggers.
    return (USHORT)USHRT_MAX;
#endif
}

static PUCHAR test_alloc_key_buf(USHORT len, UCHAR base)
{
    if (len == 0) return NULL;
    PUCHAR b = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
    if (!b) return NULL;
    for (USHORT i = 0; i < len; ++i) b[i] = (UCHAR)(base + (UCHAR)i);
    return b;
}

static BOOLEAN test_mem_eq(CONST VOID* a, CONST VOID* b, SIZE_T n)
{
    return RtlCompareMemory(a, b, n) == n;
}

/* =========================================================
   Test 1: Parameter validation
   Purpose:
     - (1.1) key==NULL and key_length>0  , NULL, no alloc/free
     - (1.2) key_length > MAX_KEY_LENGTH , NULL, no alloc/free
     - (1.3) key==NULL and key_length==0 , OK (empty key)
   ========================================================= */
BOOLEAN test_make_leaf_param_validation()
{
    TEST_START("make_leaf: parameter validation");

    // (1.1) key==NULL, len>0
    reset_mock_state();
    {
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        ART_LEAF* lf = make_leaf(NULL, (USHORT)5, 0x11111111);
        TEST_ASSERT(lf == NULL, "1.1: NULL key with nonzero length must fail");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.1: no alloc/free on guard fail");
    }

    // (1.2) length > MAX_KEY_LENGTH (guarded at compile-time to avoid truncation warnings)
    reset_mock_state();
    {
#if (MAX_KEY_LENGTH < USHRT_MAX)
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count; // only defined when used
        UCHAR dummy = 0xAB;
        const USHORT too_long = (USHORT)(MAX_KEY_LENGTH + 1u); // safe: representable in USHORT under #if
        ART_LEAF* lf = make_leaf(&dummy, too_long, 0x22222222);
        TEST_ASSERT(lf == NULL, "1.2: key_length beyond MAX_KEY_LENGTH must fail");
        TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0, "1.2: no alloc/free on guard fail");
#else
        DbgPrint("[SKIP] 1.2: MAX_KEY_LENGTH == USHRT_MAX; cannot form len > MAX_KEY_LENGTH in USHORT param\n");
#endif
    }

    // (1.3) key==NULL and len==0 , valid empty key
    reset_mock_state();
    {
        ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        ART_LEAF* lf = make_leaf(NULL, 0, 0x33333333);
        TEST_ASSERT(lf != NULL, "1.3: empty key should succeed");
        if (lf) {
            TEST_ASSERT(lf->key_length == 0, "1.3: leaf->key_length must be 0");
            TEST_ASSERT(lf->value == 0x33333333, "1.3: value must be preserved");
            TEST_ASSERT(g_alloc_call_count == a0 + 1, "1.3: one allocation for leaf");
            TEST_ASSERT(g_free_call_count == f0, "1.3: no free inside on success");
            ExFreePoolWithTag(lf, ART_TAG);
        }
    }

    TEST_END("make_leaf: parameter validation");
    return TRUE;
}

/* =========================================================
   Test 2: Allocation failure path
   Purpose:
     - Simulate ExAllocatePool2 failure , NULL, no frees
   ========================================================= */
BOOLEAN test_make_leaf_allocation_failure()
{
    TEST_START("make_leaf: allocation failure path");

    reset_mock_state();

    // 1) Allocate the input key buffer first (this must succeed)
    PUCHAR key = test_alloc_key_buf(8, 0x10);
    if (!key) {
        DbgPrint("[TEST SKIP] input key buffer alloc failed\n");
        TEST_END("make_leaf: allocation failure path");
        return TRUE;
    }

    // 2) Now force the very next allocation (the leaf itself) to fail
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 0); // fail first allocation (make_leaf)

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* lf = make_leaf(key, 8, 0x44444444);

    TEST_ASSERT(lf == NULL, "2.1: make_leaf must return NULL when allocation fails");
    TEST_ASSERT(g_alloc_call_count == a0 + 1, "2.1: one failed allocation attempt recorded");
    TEST_ASSERT(g_free_call_count == f0, "2.1: no frees should occur inside on alloc fail");

    // 3) Cleanup + restore mock knobs
    ExFreePoolWithTag(key, ART_TAG);
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, FALSE, 0);

    TEST_END("make_leaf: allocation failure path");
    return TRUE;
}

/* =========================================================
   Test 3: Successful creation with small key
   Purpose:
     - Copies key bytes exactly
     - Sets value and key_length
     - Zeroed structure
   ========================================================= */
BOOLEAN test_make_leaf_small_key_success()
{
    TEST_START("make_leaf: small key success");

    reset_mock_state();

    USHORT len = 6;
    PUCHAR key = test_alloc_key_buf(len, 0x20);
    TEST_ASSERT(key != NULL, "3-pre: input key buffer alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* lf = make_leaf(key, len, 0xAABBCCDD);
    TEST_ASSERT(lf != NULL, "3.1: make_leaf should succeed for small key");
    if (lf) {
        TEST_ASSERT(lf->key_length == len, "3.1: key_length must match input");
        TEST_ASSERT(lf->value == 0xAABBCCDD, "3.1: value must match");
        TEST_ASSERT(test_mem_eq(lf->key, key, len), "3.1: key bytes must be copied exactly");
        TEST_ASSERT(g_alloc_call_count == a0 + 1, "3.1: exactly one allocation for leaf");
        TEST_ASSERT(g_free_call_count == f0, "3.1: no free inside on success");
        ExFreePoolWithTag(lf, ART_TAG);
    }

    ExFreePoolWithTag(key, ART_TAG);

    TEST_END("make_leaf: small key success");
    return TRUE;
}

/* =========================================================
   Test 4: Zero-length key with non-NULL pointer
   Purpose:
     - len==0 should not read/copy, but succeed
   ========================================================= */
BOOLEAN test_make_leaf_zero_length_with_pointer()
{
    TEST_START("make_leaf: zero-length key with non-NULL pointer");

    reset_mock_state();

    PUCHAR dummy = test_alloc_key_buf(4, 0x55); // not used, just a non-NULL pointer
    TEST_ASSERT(dummy != NULL, "4-pre: dummy input alloc");

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* lf = make_leaf(dummy, 0, 0x01020304);
    TEST_ASSERT(lf != NULL, "4.1: zero-length key should succeed even with non-NULL key pointer");
    if (lf) {
        TEST_ASSERT(lf->key_length == 0, "4.1: key_length must be 0");
        TEST_ASSERT(lf->value == 0x01020304, "4.1: value must be preserved");
        TEST_ASSERT(g_alloc_call_count == a0 + 1, "4.1: one allocation");
        TEST_ASSERT(g_free_call_count == f0, "4.1: no free inside");
        ExFreePoolWithTag(lf, ART_TAG);
    }

    ExFreePoolWithTag(dummy, ART_TAG);

    TEST_END("make_leaf: zero-length key with non-NULL pointer");
    return TRUE;
}

/* =========================================================
   Test 5: Exact MAX_KEY_LENGTH boundary
   Purpose:
     - len == MAX_KEY_LENGTH , success
     - verify payload
   ========================================================= */
BOOLEAN test_make_leaf_max_boundary_success()
{
    TEST_START("make_leaf: MAX_KEY_LENGTH boundary");

    reset_mock_state();

    USHORT len = (USHORT)MAX_KEY_LENGTH;
    PUCHAR key = test_alloc_key_buf(len, 0x80);
    if (!key) {
        DbgPrint("[TEST SKIP] could not allocate input buffer for boundary test\n");
        TEST_END("make_leaf: MAX_KEY_LENGTH boundary");
        return TRUE;
    }

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
    ART_LEAF* lf = make_leaf(key, len, 0xCAFEBABE);
    TEST_ASSERT(lf != NULL, "5.1: boundary length should succeed");
    if (lf) {
        TEST_ASSERT(lf->key_length == len, "5.1: key_length must equal MAX_KEY_LENGTH");
        TEST_ASSERT(lf->value == 0xCAFEBABE, "5.1: value must be preserved");
        TEST_ASSERT(test_mem_eq(lf->key, key, len), "5.1: all bytes must be copied");
        TEST_ASSERT(g_alloc_call_count == a0 + 1, "5.1: one allocation");
        TEST_ASSERT(g_free_call_count == f0, "5.1: no free inside");
        ExFreePoolWithTag(lf, ART_TAG);
    }

    ExFreePoolWithTag(key, ART_TAG);

    TEST_END("make_leaf: MAX_KEY_LENGTH boundary");
    return TRUE;
}

/* =========================================================
   Test 6: Length just over MAX_KEY_LENGTH
   Purpose:
     - len == MAX_KEY_LENGTH + 1 , reject, no alloc/free
   ========================================================= */
BOOLEAN test_make_leaf_exceed_max_length()
{
    TEST_START("make_leaf: exceeding MAX_KEY_LENGTH");

    reset_mock_state();

    UCHAR some = 0x11;
    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;

    USHORT too_long = over_keylen();
    ART_LEAF* lf = make_leaf(&some, too_long, 0xAAAAAAAA);

    TEST_ASSERT(lf == NULL, "6.1: exceeding max must fail");
    TEST_ASSERT(g_alloc_call_count == a0 && g_free_call_count == f0,
        "6.1: no alloc/free on guard fail");

    TEST_END("make_leaf: exceeding MAX_KEY_LENGTH");
    return TRUE;
}

/* =========================================================
   Test 7: Stress — varied lengths including 0
   Purpose:
     - Create many leaves of different sizes; ensure all valid
       cases succeed and content matches.
   ========================================================= */
BOOLEAN test_make_leaf_stress_mixed_lengths()
{
    TEST_START("make_leaf: stress mixed lengths");

    reset_mock_state();

    const USHORT cases[] = { 0, 1, 2, 7, 15, 31, 63 };
    ART_LEAF* created[RTL_NUMBER_OF(cases)] = { 0 };
    PUCHAR     inputs[RTL_NUMBER_OF(cases)] = { 0 };

    // create
    for (ULONG i = 0; i < RTL_NUMBER_OF(cases); ++i) {
        USHORT len = cases[i];
        inputs[i] = (len == 0) ? NULL : test_alloc_key_buf(len, (UCHAR)(0x30 + (UCHAR)i));
        if (len > 0 && !inputs[i]) {
            DbgPrint("[TEST SKIP] stress: failed to alloc input length %u\n", len);
            continue;
        }
        created[i] = make_leaf(inputs[i], len, 0x12340000u + i);
        TEST_ASSERT(created[i] != NULL, "7.x: make_leaf must succeed for valid length");
        if (created[i]) {
            TEST_ASSERT(created[i]->key_length == len, "7.x: key_length must match");
            TEST_ASSERT(created[i]->value == 0x12340000u + i, "7.x: value must match");
            if (len > 0) {
                TEST_ASSERT(test_mem_eq(created[i]->key, inputs[i], len), "7.x: key content must match");
            }
        }
    }

    // cleanup
    for (ULONG i = 0; i < RTL_NUMBER_OF(cases); ++i) {
        if (created[i]) ExFreePoolWithTag(created[i], ART_TAG);
        if (inputs[i])  ExFreePoolWithTag(inputs[i], ART_TAG);
    }

    TEST_END("make_leaf: stress mixed lengths");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_make_leaf_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting make_leaf() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_make_leaf_param_validation())         all_passed = FALSE; // 1
    if (!test_make_leaf_allocation_failure())       all_passed = FALSE; // 2
    if (!test_make_leaf_small_key_success())        all_passed = FALSE; // 3
    if (!test_make_leaf_zero_length_with_pointer()) all_passed = FALSE; // 4
    if (!test_make_leaf_max_boundary_success())     all_passed = FALSE; // 5
    if (!test_make_leaf_exceed_max_length())        all_passed = FALSE; // 6
    if (!test_make_leaf_stress_mixed_lengths())     all_passed = FALSE; // 7

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL make_leaf() TESTS PASSED! \n");
    }
    else {
        DbgPrint("SOME make_leaf() TESTS FAILED! \n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
