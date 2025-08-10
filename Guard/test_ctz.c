#include "test_art.h"

STATIC inline unsigned ctz(UINT32 x);

// ---------- Helper: reference CTZ (no intrinsics) ----------
static __forceinline unsigned test_ref_ctz_u32(UINT32 x)
{
    if (x == 0u) return 32u;
    unsigned c = 0u;
    while ((x & 1u) == 0u) {
        x >>= 1;
        ++c;
    }
    return c;
}

/* =========================================================
   Test 1: Zero input
   Purpose:
     - ctz(0) must return 32 (safe guard path)
   Sub-checks:
     (1.1) Return value is 32
     (1.2) No allocations
     (1.3) No frees
   ========================================================= */
BOOLEAN test_ctz_zero_input()
{
    TEST_START("ctz: zero input");

    reset_mock_state();

    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    unsigned r = ctz(0u);

    // (1.1)
    TEST_ASSERT(r == 32u, "1.1: ctz(0) must return 32");

    // (1.2) (1.3)
    TEST_ASSERT(g_alloc_call_count == alloc_before, "1.2: No allocations must occur");
    TEST_ASSERT(g_free_call_count == free_before, "1.3: No frees must occur");

    DbgPrint("[INFO] Test 1 done: zero input returns 32 and has no side effects\n");
    TEST_END("ctz: zero input");
    return TRUE;
}

/* =========================================================
   Test 2: Single-bit sweep (positions 0..31)
   Purpose:
     - For x = (1u << k), ctz(x) must be k.
   Sub-checks (for each k):
     (2.k.1) Returned index equals k
   ========================================================= */
BOOLEAN test_ctz_single_bit_sweep()
{
    TEST_START("ctz: single-bit sweep 0..31");

    reset_mock_state();
    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    for (unsigned k = 0; k < 32u; ++k) {
        UINT32 x = (k == 31u) ? 0x80000000u : (1u << k);
        unsigned r = ctz(x);
        // (2.k.1)
        TEST_ASSERT(r == k, "2.k.1: ctz(1<<k) must equal k");
    }

    TEST_ASSERT(g_alloc_call_count == alloc_before, "2.end: No allocations in sweep");
    TEST_ASSERT(g_free_call_count == free_before, "2.end: No frees in sweep");

    DbgPrint("[INFO] Test 2 done: single-bit positions all correct\n");
    TEST_END("ctz: single-bit sweep 0..31");
    return TRUE;
}

/* =========================================================
   Test 3: Multi-bit values (lowest set bit determines result)
   Purpose:
     - When multiple bits are set, result is index of the lowest set bit.
   Sub-checks:
     (3.1) 0xFFFFFFFF -> 0
     (3.2) 0xFFFFFFFE -> 1
     (3.3) 0x80000001 -> 0
     (3.4) 0x80000000 -> 31
     (3.5) 0x00008000 -> 15
     (3.6) 0xAAAAAAAA -> 1   (…1010 pattern, LSB=0 , next bit set)
     (3.7) 0x55555555 -> 0   (…0101 pattern, LSB=1)
     (3.8) 0xF0008000 -> 15
     (3.9) 0x00C00400 -> 10
   ========================================================= */
BOOLEAN test_ctz_multi_bit_examples()
{
    TEST_START("ctz: multi-bit examples");

    reset_mock_state();
    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    // (3.1)
    TEST_ASSERT(ctz(0xFFFFFFFFu) == 0u, "3.1: ctz(0xFFFFFFFF) == 0");

    // (3.2)
    TEST_ASSERT(ctz(0xFFFFFFFEu) == 1u, "3.2: ctz(0xFFFFFFFE) == 1");

    // (3.3)
    TEST_ASSERT(ctz(0x80000001u) == 0u, "3.3: ctz(0x80000001) == 0");

    // (3.4)
    TEST_ASSERT(ctz(0x80000000u) == 31u, "3.4: ctz(0x80000000) == 31");

    // (3.5)
    TEST_ASSERT(ctz(0x00008000u) == 15u, "3.5: ctz(0x00008000) == 15");

    // (3.6)
    TEST_ASSERT(ctz(0xAAAAAAAAu) == 1u, "3.6: ctz(0xAAAAAAAA) == 1");

    // (3.7)
    TEST_ASSERT(ctz(0x55555555u) == 0u, "3.7: ctz(0x55555555) == 0");

    // (3.8)   0xF0008000 -> lowest set at bit 15
    TEST_ASSERT(ctz(0xF0008000u) == 15u, "3.8: ctz(0xF0008000) == 15");

    // (3.9)   0x00C00400 -> 0x...0100 0000 0000b , bit 10
    TEST_ASSERT(ctz(0x00C00400u) == 10u, "3.9: ctz(0x00C00400) == 10");

    TEST_ASSERT(g_alloc_call_count == alloc_before, "3.end: No allocations");
    TEST_ASSERT(g_free_call_count == free_before, "3.end: No frees");

    DbgPrint("[INFO] Test 3 done: multi-bit examples match expected indices\n");
    TEST_END("ctz: multi-bit examples");
    return TRUE;
}

/* =========================================================
   Test 4: Cross-check vs reference (deterministic LCG sequence)
   Purpose:
     - Compare ctz(x) against a simple reference implementation on
       a broad set of values without CRT/random APIs.
   Sub-checks:
     (4.i) For each generated x, ctz(x) == test_ref_ctz_u32(x)
   Notes:
     - Uses a fixed LCG to generate 256 pseudo-random UINT32 values.
   ========================================================= */
BOOLEAN test_ctz_crosscheck_lcg()
{
    TEST_START("ctz: cross-check vs reference (LCG)");

    reset_mock_state();
    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    UINT32 state = 0x13579BDFu;                // fixed seed
    const UINT32 A = 1664525u;                 // LCG constants
    const UINT32 C = 1013904223u;

    for (int i = 0; i < 256; ++i) {
        // LCG step
        state = A * state + C;

        UINT32 x = state;
        unsigned int r_ref = test_ref_ctz_u32(x);
        unsigned int r_ctz = ctz(x);

        // (4.i)
        TEST_ASSERT(r_ctz == r_ref, "4.i: ctz(x) must equal reference ctz for LCG sequence");
    }

    TEST_ASSERT(g_alloc_call_count == alloc_before, "4.end: No allocations");
    TEST_ASSERT(g_free_call_count == free_before, "4.end: No frees");

    DbgPrint("[INFO] Test 4 done: LCG cross-check passed for 256 values\n");
    TEST_END("ctz: cross-check vs reference (LCG)");
    return TRUE;
}

/* =========================================================
   Test 5: Structured pattern sweep
   Purpose:
     - Validate ctz on crafted patterns with controlled low bits.
   Sub-checks (repeated over k = 0..31):
     (5.k.1) x = (1<<k) | 0xF0F00000 , ctz(x) == k
     (5.k.2) x = (1<<k) | (1<<31)    , ctz(x) == k
   ========================================================= */
BOOLEAN test_ctz_structured_patterns()
{
    TEST_START("ctz: structured pattern sweep");

    reset_mock_state();
    ULONG alloc_before = g_alloc_call_count;
    ULONG free_before = g_free_call_count;

    for (unsigned k = 0; k < 32u; ++k) {
        UINT32 low = (k == 31u) ? 0x80000000u : (1u << k);

        // (5.k.1) add noisy high bits
        {
            UINT32 x = low | 0xF0F00000u;
            unsigned r = ctz(x);
            TEST_ASSERT(r == k, "5.k.1: noisy-high pattern must not affect lowest-bit index");
        }

        // (5.k.2) force highest bit as well
        {
            UINT32 x = low | 0x80000000u;
            unsigned r = ctz(x);
            TEST_ASSERT(r == k, "5.k.2: adding MSB must not affect lowest-bit index");
        }
    }

    TEST_ASSERT(g_alloc_call_count == alloc_before, "5.end: No allocations");
    TEST_ASSERT(g_free_call_count == free_before, "5.end: No frees");

    DbgPrint("[INFO] Test 5 done: structured patterns validated across all bit positions\n");
    TEST_END("ctz: structured pattern sweep");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_ctz_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting ctz() Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_ctz_zero_input())          all_passed = FALSE;
    if (!test_ctz_single_bit_sweep())    all_passed = FALSE;
    if (!test_ctz_multi_bit_examples())  all_passed = FALSE;
    if (!test_ctz_crosscheck_lcg())      all_passed = FALSE;
    if (!test_ctz_structured_patterns()) all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL ctz TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME ctz TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
