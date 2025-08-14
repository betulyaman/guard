#if UNIT_TEST

#include "test_art.h"

// Function under test
STATIC BOOLEAN leaf_matches(CONST ART_LEAF* leaf, CONST PUCHAR key, SIZE_T key_length);

// ---------- Helpers (FAM-aware) ----------
static ART_LEAF* test_alloc_leaf_with_key(const UCHAR* src, SIZE_T len)
{
    SIZE_T total = sizeof(ART_LEAF) + len;
    ART_LEAF* lf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, ART_TAG);
    if (!lf) return NULL;

    RtlZeroMemory(lf, total);
    lf->value = 0x4C4B40; // any marker
    lf->key_length = (USHORT)len;

    if (len > 0) {
        if (src) RtlCopyMemory(lf->key, src, len);
        else RtlZeroMemory(lf->key, len);
    }
    return lf;
}

/* =====================================================================
   Test 1: Invalid-parameter gates (early FALSE)
   Purpose:
     Validate all early exit conditions that are meaningful with FAM.
   Notes:
     With a flexible array member, the expression `!leaf->key` is not
     constructible as NULL in well-formed allocations; therefore we do
     NOT test a “leaf->key == NULL” scenario here.
   Sub-checks:
     (1.1) leaf == NULL
     (1.2) key == NULL
     (1.3) key_length == 0
     (1.4) key_length > MAX_PREFIX_LENGTH
     (1.5) leaf->key_length == 0 (zero-length leaf)
   ===================================================================== */
BOOLEAN test_leaf_matches_invalid_params_fam()
{
    TEST_START("leaf_matches (FAM): invalid parameter gates");

    // (1.1) leaf == NULL
    reset_mock_state();
    {
        UCHAR dummy[1] = { 0x11 };
        BOOLEAN ok = leaf_matches(NULL, dummy, 1);
        TEST_ASSERT(ok == FALSE, "1.1: NULL leaf must return FALSE");
        TEST_ASSERT(g_alloc_call_count == 0 && g_free_call_count == 0, "1.1: No alloc/free");
    }

    // (1.2) key == NULL
    reset_mock_state();
    {
        UCHAR k[] = { 0xAA };
        ART_LEAF* lf = test_alloc_leaf_with_key(k, sizeof(k));
        TEST_ASSERT(lf != NULL, "1.2-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, NULL, 1);
        TEST_ASSERT(ok == FALSE, "1.2: NULL key must return FALSE");
        test_free_leaf(lf);
    }

    // (1.3) key_length == 0
    reset_mock_state();
    {
        UCHAR k[] = { 0xBB };
        ART_LEAF* lf = test_alloc_leaf_with_key(k, sizeof(k));
        TEST_ASSERT(lf != NULL, "1.3-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, k, 0);
        TEST_ASSERT(ok == FALSE, "1.3: key_length==0 must return FALSE");
        test_free_leaf(lf);
    }

    // (1.4) key_length > MAX_KEY_LENGTH  // match function's guard
    reset_mock_state();
    {
        UCHAR one = 0xCD;
        ART_LEAF* lf = test_alloc_leaf_with_key(&one, 1);
        TEST_ASSERT(lf != NULL, "1.4-pre: leaf allocation");
        SIZE_T too_large = (SIZE_T)MAX_KEY_LENGTH + 1;
        BOOLEAN ok = leaf_matches(lf, &one, too_large);
        TEST_ASSERT(ok == FALSE, "1.4: key_length > MAX_KEY_LENGTH must return FALSE");
        test_free_leaf(lf);
    }

    // (1.5) leaf->key_length == 0 (zero-length leaf)
    reset_mock_state();
    {
        ART_LEAF* lf = test_alloc_leaf_with_key(NULL, 0); // FAM with length 0
        TEST_ASSERT(lf != NULL, "1.5-pre: zero-length leaf allocation");
        UCHAR k[] = { 0x01 };
        BOOLEAN ok = leaf_matches(lf, k, 1);
        TEST_ASSERT(ok == FALSE, "1.5: zero-length leaf must return FALSE");
        test_free_leaf(lf);
    }

    // (1.6) leaf->key_length > MAX_KEY_LENGTH  // new: exercise the leaf-side guard
    reset_mock_state();
    {
        SIZE_T too_long = (SIZE_T)MAX_KEY_LENGTH + 1;
        // Allocate a leaf with a key longer than MAX_KEY_LENGTH; helper stores len into key_length.
        PUCHAR big = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, too_long, ART_TAG);
        TEST_ASSERT(big != NULL, "1.6-pre: big key buffer allocation");
        if (big) { RtlFillMemory(big, too_long, 0xAB); }

        ART_LEAF* lf = test_alloc_leaf_with_key(big, too_long);
        TEST_ASSERT(lf != NULL, "1.6-pre: leaf allocation with oversized key_length");
        // Probe with any non-null key/len to pass the other gates.
        BOOLEAN ok = leaf_matches(lf, big, MAX_KEY_LENGTH);
        TEST_ASSERT(ok == FALSE, "1.6: leaf->key_length > MAX_KEY_LENGTH must return FALSE");

        if (big) { ExFreePool2(big, ART_TAG, NULL, 0); }
        test_free_leaf(lf);
    }

    LOG_MSG("[INFO] Test 1: all reachable invalid-parameter gates return FALSE (FAM)\n");
    TEST_END("leaf_matches (FAM): invalid parameter gates");
    return TRUE;
}

/* =====================================================================
   Test 2: Length mismatch
   Purpose:
     After gates pass, any length difference must return FALSE.
   Sub-checks:
     (2.1) leaf shorter than key
     (2.2) leaf longer than key
   ===================================================================== */
BOOLEAN test_leaf_matches_length_mismatch_fam()
{
    TEST_START("leaf_matches (FAM): length mismatch");

    // (2.1) leaf shorter
    reset_mock_state();
    {
        UCHAR leaf_key[] = { 0x10, 0x20 };
        UCHAR probe[] = { 0x10, 0x20, 0x30 };
        ART_LEAF* lf = test_alloc_leaf_with_key(leaf_key, sizeof(leaf_key));
        TEST_ASSERT(lf != NULL, "2.1-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, probe, sizeof(probe));
        TEST_ASSERT(ok == FALSE, "2.1: length mismatch -> FALSE");
        test_free_leaf(lf);
    }

    // (2.2) leaf longer
    reset_mock_state();
    {
        UCHAR leaf_key[] = { 0xAA, 0xBB, 0xCC };
        UCHAR probe[] = { 0xAA, 0xBB };
        ART_LEAF* lf = test_alloc_leaf_with_key(leaf_key, sizeof(leaf_key));
        TEST_ASSERT(lf != NULL, "2.2-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, probe, sizeof(probe));
        TEST_ASSERT(ok == FALSE, "2.2: length mismatch -> FALSE");
        test_free_leaf(lf);
    }

    LOG_MSG("[INFO] Test 2: length mismatches correctly rejected (FAM)\n");
    TEST_END("leaf_matches (FAM): length mismatch");
    return TRUE;
}

/* =====================================================================
   Test 3: Exact match (including embedded NULs, boundary)
   Purpose:
     When lengths are equal and all bytes match, return TRUE.
   Sub-checks:
     (3.1) Simple ASCII-like payload
     (3.2) Binary with embedded 0x00
     (3.3) Boundary at MAX_PREFIX_LENGTH
   ===================================================================== */
BOOLEAN test_leaf_matches_exact_matches_fam()
{
    TEST_START("leaf_matches (FAM): exact matches");

    // (3.1) simple ASCII-like
    reset_mock_state();
    {
        const UCHAR key[] = { 'a','b','c','_','1','2' };
        ART_LEAF* lf = test_alloc_leaf_with_key(key, sizeof(key));
        TEST_ASSERT(lf != NULL, "3.1-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, (const PUCHAR)key, sizeof(key));
        TEST_ASSERT(ok == TRUE, "3.1: exact bytes -> TRUE");
        test_free_leaf(lf);
    }

    // (3.2) embedded NULs
    reset_mock_state();
    {
        UCHAR key[] = { 0x00, 0x11, 0x00, 0x22, 0x00 };
        ART_LEAF* lf = test_alloc_leaf_with_key(key, sizeof(key));
        TEST_ASSERT(lf != NULL, "3.2-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, key, sizeof(key));
        TEST_ASSERT(ok == TRUE, "3.2: exact binary match with NULs -> TRUE");
        test_free_leaf(lf);
    }

    // (3.3) boundary at MAX_KEY_LENGTH
    reset_mock_state();
    {
        SIZE_T len = (SIZE_T)MAX_KEY_LENGTH;
        PUCHAR buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
        TEST_ASSERT(buf != NULL, "3.3-pre: boundary buffer allocation");
        if (buf)
        {
            for (SIZE_T i = 0; i < len; ++i)
            {
                buf[i] = (UCHAR)(i & 0xFF);
            }
        }

        ART_LEAF* lf = test_alloc_leaf_with_key(buf, len);
        TEST_ASSERT(lf != NULL, "3.3-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, buf, len);
        TEST_ASSERT(ok == TRUE, "3.3: boundary-sized exact match -> TRUE");

        if (buf) { ExFreePool2(buf, ART_TAG, NULL, 0); }
        test_free_leaf(lf);
    }

    LOG_MSG("[INFO] Test 3: exact match scenarios succeed (FAM)\n");
    TEST_END("leaf_matches (FAM): exact matches");
    return TRUE;
}


/* =====================================================================
   Test 4: Same length, byte mismatches
   Purpose:
     If any byte differs (first/middle/last), return FALSE.
   Sub-checks:
     (4.1) First byte differs
     (4.2) Middle byte differs
     (4.3) Last byte differs
   ===================================================================== */
BOOLEAN test_leaf_matches_byte_mismatches_fam()
{
    TEST_START("leaf_matches (FAM): byte-level mismatches");

    // (4.1) first-byte mismatch
    reset_mock_state();
    {
        UCHAR a[] = { 0x01, 0x22, 0x33, 0x44 };
        UCHAR b[] = { 0xFF, 0x22, 0x33, 0x44 };
        ART_LEAF* lf = test_alloc_leaf_with_key(a, sizeof(a));
        TEST_ASSERT(lf != NULL, "4.1-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, b, sizeof(b));
        TEST_ASSERT(ok == FALSE, "4.1: first-byte mismatch -> FALSE");
        test_free_leaf(lf);
    }

    // (4.2) middle-byte mismatch
    reset_mock_state();
    {
        UCHAR a[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        UCHAR b[] = { 0x10, 0x20, 0xFF, 0x40, 0x50 };
        ART_LEAF* lf = test_alloc_leaf_with_key(a, sizeof(a));
        TEST_ASSERT(lf != NULL, "4.2-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, b, sizeof(b));
        TEST_ASSERT(ok == FALSE, "4.2: middle-byte mismatch -> FALSE");
        test_free_leaf(lf);
    }

    // (4.3) last-byte mismatch
    reset_mock_state();
    {
        UCHAR a[] = { 0xAA, 0xBB, 0xCC };
        UCHAR b[] = { 0xAA, 0xBB, 0xCD };
        ART_LEAF* lf = test_alloc_leaf_with_key(a, sizeof(a));
        TEST_ASSERT(lf != NULL, "4.3-pre: leaf allocation");
        BOOLEAN ok = leaf_matches(lf, b, sizeof(b));
        TEST_ASSERT(ok == FALSE, "4.3: last-byte mismatch -> FALSE");
        test_free_leaf(lf);
    }

    LOG_MSG("[INFO] Test 4: any byte mismatch correctly returns FALSE (FAM)\n");
    TEST_END("leaf_matches (FAM): byte-level mismatches");
    return TRUE;
}

/* =====================================================================
   Test 5: Sequence sweep 1..32 (positive/negative)
   Purpose:
     Light fuzz to exercise RtlCompareMemory path with FAM layout.
   Sub-checks (for each length L):
     (5.L.1) Exact match returns TRUE
     (5.L.2) Single-byte flip returns FALSE
   ===================================================================== */
BOOLEAN test_leaf_matches_sequence_sweep_fam()
{
    TEST_START("leaf_matches (FAM): sequence sweep 1..32");

    reset_mock_state();

    for (SIZE_T len = 1; len <= 32; ++len) {
        PUCHAR a = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
        PUCHAR b = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
        TEST_ASSERT(a && b, "5.pre: buffer allocations");

        for (SIZE_T i = 0; i < len; ++i) { a[i] = (UCHAR)(i + 1); b[i] = (UCHAR)(i + 1); }

        ART_LEAF* lf = test_alloc_leaf_with_key(a, len);
        TEST_ASSERT(lf != NULL, "5.pre: leaf allocation");

        // (5.L.1) exact
        {
            BOOLEAN ok = leaf_matches(lf, b, len);
            TEST_ASSERT(ok == TRUE, "5.L.1: exact bytes -> TRUE");
        }

        // (5.L.2) flip last byte
        {
            b[len - 1] ^= 0xFF;
            BOOLEAN ok = leaf_matches(lf, b, len);
            TEST_ASSERT(ok == FALSE, "5.L.2: single-byte flip -> FALSE");
        }

        ExFreePool2(a, ART_TAG, NULL, 0);
        ExFreePool2(b, ART_TAG, NULL, 0);
        test_free_leaf(lf);
    }

    LOG_MSG("[INFO] Test 5: sweep over 1..32 passed (FAM)\n");
    TEST_END("leaf_matches (FAM): sequence sweep 1..32");
    return TRUE;
}

/* =====================================================================
   Suite Runner (FAM)
   ===================================================================== */
NTSTATUS run_all_leaf_matches_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting leaf_matches (FAM) Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_leaf_matches_invalid_params_fam())        all_passed = FALSE;
    if (!test_leaf_matches_length_mismatch_fam())       all_passed = FALSE;
    if (!test_leaf_matches_exact_matches_fam())         all_passed = FALSE;
    if (!test_leaf_matches_byte_mismatches_fam())       all_passed = FALSE;
    if (!test_leaf_matches_sequence_sweep_fam())        all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL leaf_matches (FAM) TESTS PASSED! \n");
    }
    else {
        LOG_MSG("SOME leaf_matches (FAM) TESTS FAILED! \n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif