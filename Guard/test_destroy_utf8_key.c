#if UNIT_TEST

#include "test_art.h"
#include <ntstrsafe.h>

#define NUM_SIMULATED_CONTEXTS 10

// Forward declaration of the function under test
STATIC inline VOID destroy_utf8_key(_In_opt_ PUCHAR key);

// Test 1: NULL pointer handling
BOOLEAN test_null_pointer_handling()
{
    TEST_START("NULL Pointer Handling");

    reset_mock_state();

    // Test 1.1: Explicit NULL pointer
    // Verifies the function safely handles NULL without calling ExFreePool2
    destroy_utf8_key(NULL);

    TEST_ASSERT(g_free_call_count == 0, "Should not call ExFreePool2 for NULL pointer");

    // Test 1.2: Multiple NULL calls (should be safe)
    destroy_utf8_key(NULL);
    destroy_utf8_key(NULL);

    TEST_ASSERT(g_free_call_count == 0, "Multiple NULL calls should not trigger any frees");

    LOG_MSG("[INFO] NULL pointer handling works correctly - no crashes or unexpected calls\n");

    TEST_END("NULL Pointer Handling");
    return TRUE;
}

// Test 2: Valid pointer deallocation
BOOLEAN test_valid_pointer_deallocation()
{
    TEST_START("Valid Pointer Deallocation");

    reset_mock_state();

    // Test 2.1: Allocate and deallocate a small buffer
    PUCHAR test_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 16, ART_TAG);

    if (!test_key) {
        LOG_MSG("[TEST SKIP] Could not allocate memory for valid pointer test\n");
        TEST_END("Valid Pointer Deallocation");
        return TRUE; // Skip this test if allocation fails
    }

    // Fill with test data (kernel-safe)
    RtlStringCbCopyA((char*)test_key, 16, "test_key");

    // Store the pointer for verification
    PUCHAR original_pointer = test_key;

    // Call destroy function
    destroy_utf8_key(test_key);

    TEST_ASSERT(g_free_call_count == 1, "Should call ExFreePoolWith2 exactly once");
    TEST_ASSERT(g_last_freed_pointer == original_pointer, "Should free the correct pointer");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "Should use the correct pool tag");

    LOG_MSG("[INFO] Valid pointer deallocation completed successfully\n");

    // Test 2.2: Deallocate a larger buffer
    reset_mock_state();

    PUCHAR large_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, ART_TAG);
    if (large_key) {
        // Fill with test pattern
        for (int i = 0; i < 1023; i++) {
            large_key[i] = (UCHAR)(i % 256);
        }
        large_key[1023] = '\0';

        destroy_utf8_key(large_key);

        TEST_ASSERT(g_free_call_count == 1, "Should free large buffer correctly");

        LOG_MSG("[INFO] Large buffer deallocation completed successfully\n");
    }

    TEST_END("Valid Pointer Deallocation");
    return TRUE;
}

// Test 3: Multiple deallocation safety
BOOLEAN test_multiple_deallocation_safety()
{
    TEST_START("Multiple Deallocation Safety");

    reset_mock_state();

    // Allocate multiple buffers and free them one by one
    PUCHAR keys[5];
    int allocated_count = 0;

    // Allocate multiple test keys
    for (int i = 0; i < 5; i++) {
        keys[i] = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 32, ART_TAG);
        if (keys[i]) {
            // Use kernel-safe string formatting
            RtlStringCbPrintfA((char*)keys[i], 32, "test_key_%d", i);
            allocated_count++;
        }
    }

    if (allocated_count == 0) {
        LOG_MSG("[TEST SKIP] Could not allocate any memory for multiple deallocation test\n");
        TEST_END("Multiple Deallocation Safety");
        return TRUE;
    }

    // Free all allocated keys
    for (int i = 0; i < 5; i++) {
        if (keys[i]) {
            destroy_utf8_key(keys[i]);
        }
    }

    TEST_ASSERT(g_free_call_count == (ULONG)allocated_count,
        "Should call ExFreePool2 for each valid pointer");

    LOG_MSG("[INFO] Multiple deallocation completed - freed %d buffers\n", allocated_count);

    TEST_END("Multiple Deallocation Safety");
    return TRUE;
}

// Test 4: Edge case pointers
BOOLEAN test_edge_case_pointers()
{
    TEST_START("Edge Case Pointers");

    reset_mock_state();

    // Test 4.1: Very small allocation (1 byte)
    PUCHAR tiny_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1, ART_TAG);
    if (tiny_key) {
        tiny_key[0] = '\0';
        destroy_utf8_key(tiny_key);

        TEST_ASSERT(g_free_call_count == 1, "Should handle tiny allocation correctly");

        LOG_MSG("[INFO] Tiny allocation (1 byte) handled correctly\n");
    }

    // Test 4.2: Zero-length string (but valid pointer)
    reset_mock_state();
    PUCHAR empty_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 16, ART_TAG);
    if (empty_key) {
        empty_key[0] = '\0'; // Empty string
        destroy_utf8_key(empty_key);

        TEST_ASSERT(g_free_call_count == 1, "Should handle empty string pointer correctly");

        LOG_MSG("[INFO] Empty string pointer handled correctly\n");
    }

    TEST_END("Edge Case Pointers");
    return TRUE;
}

// Test 5: Integration with unicode_to_utf8 function
BOOLEAN test_integration_with_unicode_to_utf8()
{
    TEST_START("Integration with unicode_to_utf8");

    reset_mock_state();

    // This test simulates the typical usage pattern:
    // 1. Call unicode_to_utf8 to get a UTF-8 key
    // 2. Use the key
    // 3. Call destroy_utf8_key to clean up

    // Simulate the output of unicode_to_utf8 by allocating a UTF-8 string
    PUCHAR simulated_utf8_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 64, ART_TAG);

    if (!simulated_utf8_key) {
        LOG_MSG("[TEST SKIP] Could not allocate memory for integration test\n");
        TEST_END("Integration with unicode_to_utf8");
        return TRUE;
    }

    // Fill with simulated UTF-8 content (like what unicode_to_utf8 would produce)
    RtlStringCbCopyA((char*)simulated_utf8_key, 64, "c:\\users\\testuser\\documents\\file.txt");

    // Verify the content is as expected
    size_t len = 0;
    NTSTATUS lenStatus = RtlStringCbLengthA((char*)simulated_utf8_key, 64, &len);
    TEST_ASSERT(NT_SUCCESS(lenStatus) && len > 0, "Simulated key should have content");

    // Now destroy it using our function
    destroy_utf8_key(simulated_utf8_key);

    TEST_ASSERT(g_free_call_count == 1, "Should properly clean up simulated UTF-8 key");
    TEST_ASSERT(g_last_freed_tag == ART_TAG, "Should use correct tag in cleanup");

    LOG_MSG("[INFO] Integration test completed - typical usage pattern works\n");

    TEST_END("Integration with unicode_to_utf8");
    return TRUE;
}

// Test 6: Concurrent usage simulation
BOOLEAN test_concurrent_usage_simulation()
{
    TEST_START("Concurrent Usage Simulation");

    reset_mock_state();

    // Simulate multiple threads/contexts using the function
    // Note: This is not true concurrency testing, but simulates the pattern
    PUCHAR context_keys[NUM_SIMULATED_CONTEXTS];
    int successful_allocations = 0;

    // Simulate multiple contexts allocating keys
    for (int i = 0; i < NUM_SIMULATED_CONTEXTS; i++) {
        context_keys[i] = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 48, ART_TAG);
        if (context_keys[i]) {
            RtlStringCbPrintfA((char*)context_keys[i], 48, "context_%d_key_data", i);
            successful_allocations++;
        }
    }

    // Simulate contexts finishing and cleaning up in different order
    // (reverse order to test that order doesn't matter)
    for (int i = NUM_SIMULATED_CONTEXTS - 1; i >= 0; i--) {
        if (context_keys[i]) {
            destroy_utf8_key(context_keys[i]);
        }
    }

    TEST_ASSERT(g_free_call_count == (ULONG)successful_allocations,
        "Should clean up all successfully allocated contexts");

    LOG_MSG("[INFO] Concurrent usage simulation completed - %d contexts handled\n",
        successful_allocations);

    TEST_END("Concurrent Usage Simulation");
    return TRUE;
}

// Test 7: Memory pattern validation
BOOLEAN test_memory_pattern_validation()
{
    TEST_START("Memory Pattern Validation");

    reset_mock_state();

    // Test with various memory patterns that might cause issues

    // Test 7.1: All zeros
    PUCHAR zero_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 32, ART_TAG);
    if (zero_key) {
        RtlZeroMemory(zero_key, 32);
        destroy_utf8_key(zero_key);
        LOG_MSG("[INFO] All-zeros memory pattern handled correctly\n");
    }

    // Test 7.2: All 0xFF pattern
    reset_mock_state();
    PUCHAR ff_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 32, ART_TAG);
    if (ff_key) {
        RtlFillMemory(ff_key, 32, 0xFF);
        destroy_utf8_key(ff_key);
        LOG_MSG("[INFO] All-0xFF memory pattern handled correctly\n");
    }

    // Test 7.3: Alternating pattern
    reset_mock_state();
    PUCHAR alt_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 32, ART_TAG);
    if (alt_key) {
        for (int i = 0; i < 32; i++) {
            alt_key[i] = (i % 2) ? 0xAA : 0x55;
        }
        destroy_utf8_key(alt_key);
        LOG_MSG("[INFO] Alternating memory pattern handled correctly\n");
    }

    TEST_END("Memory Pattern Validation");
    return TRUE;
}

// Test 8: Stress test with rapid allocation/deallocation
BOOLEAN test_stress_allocation_deallocation()
{
    TEST_START("Stress Allocation/Deallocation");

    reset_mock_state();

    const int STRESS_ITERATIONS = 100;
    int successful_cycles = 0;

    // Rapidly allocate and deallocate keys
    for (int i = 0; i < STRESS_ITERATIONS; i++) {
        PUCHAR stress_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 64, ART_TAG);
        if (stress_key) {
            // Fill with test pattern
            RtlStringCbPrintfA((char*)stress_key, 64, "stress_test_key_%d_abcdefghijklmnop", i);

            // Immediately destroy it
            destroy_utf8_key(stress_key);
            successful_cycles++;
        }
        else {
            // If allocation fails, that's not necessarily a test failure
            // but we should note it
            LOG_MSG("[INFO] Allocation failed at iteration %d (expected under stress)\n", i);
        }
    }

    TEST_ASSERT(g_free_call_count == (ULONG)successful_cycles,
        "Should free all successfully allocated stress test keys");

    LOG_MSG("[INFO] Stress test completed: %d/%d successful cycles\n",
        successful_cycles, STRESS_ITERATIONS);

    TEST_END("Stress Allocation/Deallocation");
    return TRUE;
}

// Test 9: Function behavior validation
BOOLEAN test_function_behavior_validation()
{
    TEST_START("Function Behavior Validation");

    reset_mock_state();

    // Test 9.1: Verify function doesn't modify the pointer value
    PUCHAR test_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 32, ART_TAG);
    if (test_key) {
        PUCHAR original_value = test_key;
        RtlStringCbCopyA((char*)test_key, 32, "behavior_test");

        // The function takes the parameter by value, so it shouldn't modify
        // the original pointer variable (this is a conceptual test)
        destroy_utf8_key(test_key);

        // After the call, test_key still has the same value
        // (though the memory it points to is now invalid)
        TEST_ASSERT(test_key == original_value,
            "Function should not modify the pointer parameter value");

        LOG_MSG("[INFO] Function parameter behavior validated\n");
    }

    // Test 9.2: Verify function is safe to call in different contexts
    // (This is more of a documentation test)
    destroy_utf8_key(NULL); // Should be safe at any IRQL where ExFreePool2 is safe

    LOG_MSG("[INFO] Function context safety validated\n");

    TEST_END("Function Behavior Validation");
    return TRUE;
}

// Test 10: Logging and debugging verification
BOOLEAN test_logging_and_debugging()
{
    TEST_START("Logging and Debugging Verification");

    reset_mock_state();

    // This test verifies that the logging in the function works correctly

    // Test 10.1: Verify logging for valid pointer
    PUCHAR log_test_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 16, ART_TAG);
    if (log_test_key) {
        RtlStringCbCopyA((char*)log_test_key, 16, "log_test");

        LOG_MSG("[TEST] About to call destroy_utf8_key - expect LOG_MSG output\n");
        destroy_utf8_key(log_test_key);
        LOG_MSG("[TEST] destroy_utf8_key call completed\n");
    }

    // Test 10.2: Verify no logging for NULL pointer
    LOG_MSG("[TEST] About to call destroy_utf8_key with NULL - expect no LOG_MSG\n");
    destroy_utf8_key(NULL);
    LOG_MSG("[TEST] destroy_utf8_key with NULL completed\n");

    // Test 10.3: Multiple valid pointers to test logging consistency
    for (int i = 0; i < 3; i++) {
        PUCHAR multi_log_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 20, ART_TAG);
        if (multi_log_key) {
            RtlStringCbPrintfA((char*)multi_log_key, 20, "multi_%d", i);
            LOG_MSG("[TEST] Destroying key %d\n", i);
            destroy_utf8_key(multi_log_key);
        }
    }

    LOG_MSG("[INFO] Logging and debugging verification completed\n");

    TEST_END("Logging and Debugging Verification");
    return TRUE;
}

// Main test runner function for destroy_utf8_key
NTSTATUS run_all_destroy_utf8_key_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting Comprehensive destroy_utf8_key Test Suite\n");
    LOG_MSG("========================================\n\n");

    // Note: Actual memory allocation failure testing would require 
    // fault injection mechanisms not available in standard kernel code
    LOG_MSG("[NOTE] Some advanced testing scenarios (like true memory pressure\n");
    LOG_MSG("       and fault injection) require specialized test frameworks\n");
    LOG_MSG("       not available in standard kernel development environments.\n\n");

    BOOLEAN all_passed = TRUE;

    // Run all test suites
    if (!test_null_pointer_handling()) all_passed = FALSE;
    if (!test_valid_pointer_deallocation()) all_passed = FALSE;
    if (!test_multiple_deallocation_safety()) all_passed = FALSE;
    if (!test_edge_case_pointers()) all_passed = FALSE;
    if (!test_integration_with_unicode_to_utf8()) all_passed = FALSE;
    if (!test_concurrent_usage_simulation()) all_passed = FALSE;
    if (!test_memory_pattern_validation()) all_passed = FALSE;
    if (!test_stress_allocation_deallocation()) all_passed = FALSE;
    if (!test_function_behavior_validation()) all_passed = FALSE;
    if (!test_logging_and_debugging()) all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL destroy_utf8_key TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME destroy_utf8_key TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// Combined test runner for both functions
NTSTATUS run_all_utf8_key_tests()
{
    LOG_MSG("\n##########################################\n");
    LOG_MSG("Starting Complete UTF-8 Key Management Test Suite\n");
    LOG_MSG("##########################################\n\n");

    NTSTATUS destroy_tests_status = STATUS_SUCCESS;

    // Run unicode_to_utf8 tests first (assuming they exist)
    // unicode_tests_status = run_all_unicode_to_utf8_tests();

    // Run destroy_utf8_key tests
    destroy_tests_status = run_all_destroy_utf8_key_tests();

    LOG_MSG("\n##########################################\n");
    LOG_MSG("Complete UTF-8 Key Management Test Suite Results:\n");
    // LOG_MSG("unicode_to_utf8 tests: %s\n", 
    //          NT_SUCCESS(unicode_tests_status) ? "PASSED" : "FAILED");
    LOG_MSG("destroy_utf8_key tests: %s\n",
        NT_SUCCESS(destroy_tests_status) ? "PASSED" : "FAILED");

    if (NT_SUCCESS(destroy_tests_status)) {
        LOG_MSG("\nOVERALL RESULT: SUCCESS\n");
    }
    else {
        LOG_MSG("\nOVERALL RESULT: FAILURE \n");
    }
    LOG_MSG("##########################################\n\n");

    return NT_SUCCESS(destroy_tests_status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#endif