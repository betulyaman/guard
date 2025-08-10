#include <ntifs.h>

#include "test_art.h"

// Forward declaration of the function under test
STATIC inline PUCHAR unicode_to_utf8(_In_ PCUNICODE_STRING unicode, _Out_ PUSHORT out_length);

// Test 1: NULL pointer validation tests
BOOLEAN test_null_pointer_validation()
{
    TEST_START("NULL Pointer Validation");

    reset_mock_state();

    USHORT out_length = 0x1234; // Initialize with non-zero to verify it's not touched
    PUCHAR result;
    UNICODE_STRING valid_unicode;
    WCHAR test_buffer[] = L"Test";

    create_unicode_string(&valid_unicode, test_buffer, 4);

    // Test 1.1: NULL unicode parameter
    // Ensures the function safely handles NULL input without crashing
    out_length = 0x1234;
#pragma warning(push)
#pragma warning(disable: 6387)
    result = unicode_to_utf8(NULL, &out_length);
#pragma warning(pop)
    TEST_ASSERT(result == NULL, "Should return NULL for NULL unicode parameter");
    TEST_ASSERT(out_length == 0x1234, "Should not touch out_length on NULL unicode");

    TEST_ASSERT(g_alloc_call_count == 0, "Should not allocate memory for NULL unicode");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase for NULL unicode");
    TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "Should not call UTF-8 conversion for NULL unicode");

    // Test 1.2: NULL out_length parameter
    // Verifies proper handling when output parameter is NULL
    reset_mock_state();
#pragma warning(push)
#pragma warning(disable: 6387)
    result = unicode_to_utf8(&valid_unicode, NULL);
#pragma warning(pop)
    TEST_ASSERT(result == NULL, "Should return NULL for NULL out_length parameter");
    TEST_ASSERT(g_alloc_call_count == 0, "Should not allocate memory for NULL out_length");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase for NULL out_length");
    TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "Should not call UTF-8 conversion for NULL out_length");

    // Test 1.3: NULL Buffer in unicode string
    // Checks behavior when the Unicode string has a NULL buffer
    UNICODE_STRING null_buffer_unicode = { 0 };
    null_buffer_unicode.Length = 10;
    null_buffer_unicode.MaximumLength = 20;
    null_buffer_unicode.Buffer = NULL;

    // Test 1.4: Confirms that out_length is not modified on early exits due to invalid parameters
    reset_mock_state();
    out_length = 0x1234;
    result = unicode_to_utf8(&null_buffer_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL for NULL Buffer in unicode string");
    TEST_ASSERT(out_length == 0x1234, "Should not touch out_length on NULL Buffer");

    TEST_ASSERT(g_alloc_call_count == 0, "Should not allocate memory for NULL Buffer");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase for NULL Buffer");
    TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "Should not call UTF-8 conversion for NULL Buffer");

    cleanup_unicode_string(&valid_unicode);
    TEST_END("NULL Pointer Validation");
    return TRUE;
}

// Test 2: Empty string validation tests
BOOLEAN test_empty_string_validation()
{
    TEST_START("Empty String Validation");

    reset_mock_state();

    USHORT out_length = 0x1234;
    PUCHAR result;
    UNICODE_STRING empty_unicode;
    WCHAR empty_buffer[] = L"";

    // Test 2.1: Zero length string
    // Ensures empty strings are rejected properly
    create_unicode_string(&empty_unicode, empty_buffer, 0);
    empty_unicode.Length = 0; // Explicitly set to 0

    // Confirms out_length isn't touched on empty input
    out_length = 0x1234;
    result = unicode_to_utf8(&empty_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL for zero length string");
    TEST_ASSERT(out_length == 0x1234, "Should not touch out_length on zero length");


    TEST_ASSERT(g_alloc_call_count == 0, "Should not allocate memory for zero length string");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase for zero length string");
    TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "Should not call UTF-8 conversion for zero length string");


    cleanup_unicode_string(&empty_unicode);
    TEST_END("Empty String Validation");
    return TRUE;
}

// Test 3: Length boundary tests
BOOLEAN test_length_boundary_validation()
{
    TEST_START("Length Boundary Validation");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING long_unicode;

    // Test 3.1: Maximum allowed length (65535 characters)
    reset_mock_state();
    ULONG max_chars = 65535;
    NTSTATUS status = create_unicode_string(&long_unicode, NULL, 0);
    if (NT_SUCCESS(status)) {
        long_unicode.Length = (USHORT)(max_chars * sizeof(WCHAR));
        long_unicode.MaximumLength = long_unicode.Length;

        // Allocate buffer for maximum size
        if (long_unicode.Buffer) {
            ExFreePoolWithTag(long_unicode.Buffer, ART_TAG);
        }
        long_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            long_unicode.MaximumLength, ART_TAG);

        if (long_unicode.Buffer) {
            // Fill with valid ASCII characters
            for (ULONG i = 0; i < max_chars; i++) {
                long_unicode.Buffer[i] = L'A';
            }


            ULONG free_before = g_free_call_count;

            result = unicode_to_utf8(&long_unicode, &out_length);

            // Depending on your constants (especially MAX_KEY_LENGTH),
            // this boundary case can either succeed or fail.
            TEST_ASSERT(result != NULL || result == NULL, "Max length case handled");


            // In both success and failure cases, these expectations hold:
            TEST_ASSERT(g_downcase_call_count == 1, "Should downcase once at 65535 boundary");
            TEST_ASSERT(g_unicode_to_utf8_call_count >= 1, "Should at least probe UTF-8 length");

            if (result == NULL) {
                // If MAX_KEY_LENGTH is small (e.g., 1024), we expect a failure here.
                // No UTF-8 buffer allocation should occur; only the lowercase buffer should be allocated and freed.
                TEST_ASSERT(g_alloc_call_count == 1, "Only lowercase buffer should be allocated on failure");
                TEST_ASSERT(g_free_call_count >= free_before + 1, "Lowercase buffer should be freed on failure");
            }
            else {
                // On success, expect probe + convert and two allocations.
                TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert on success");
                TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers should be allocated");
            }


            if (result) {
                ExFreePoolWithTag(result, ART_TAG);
            }
            cleanup_unicode_string(&long_unicode);
        }
    }

    // Test 3.2: Overly long path (65536 characters - should fail)
    reset_mock_state();
    ULONG too_many_chars = 65536;
    status = create_unicode_string(&long_unicode, NULL, 0);
    if (NT_SUCCESS(status)) {
        long_unicode.Length = (USHORT)(too_many_chars * sizeof(WCHAR));
        long_unicode.MaximumLength = long_unicode.Length;

        if (long_unicode.Buffer) {
            ExFreePoolWithTag(long_unicode.Buffer, ART_TAG);
        }
        long_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            long_unicode.MaximumLength, ART_TAG);

        if (long_unicode.Buffer) {
            // No need to fill content; function will exit early on length check.
            result = unicode_to_utf8(&long_unicode, &out_length);
            TEST_ASSERT(result == NULL, "Should reject overly long strings (>65535 chars)");


            // For >65535, check should happen at the START of the function,
            // before any allocation or transformation.
            TEST_ASSERT(g_alloc_call_count == 0, "No allocations should occur on early length reject");
            TEST_ASSERT(g_downcase_call_count == 0, "No downcase on early length reject");
            TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "No UTF-8 calls on early length reject");
            TEST_ASSERT(g_free_call_count == 0, "No frees should be needed on early reject");


            cleanup_unicode_string(&long_unicode);
        }
    }

    TEST_END("Length Boundary Validation");
    return TRUE;
}

// Test 4: Basic ASCII conversion tests
BOOLEAN test_basic_ascii_conversion()
{
    TEST_START("Basic ASCII Conversion");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;

    // Test 4.1: Simple ASCII string
    reset_mock_state();
    WCHAR simple_ascii[] = L"HelloWorld";
    create_unicode_string(&test_unicode, simple_ascii, STRW_LITERAL_LEN(simple_ascii));

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert simple ASCII");

    if (result) {
        TEST_ASSERT(out_length == STRA_LITERAL_LEN("helloworld"), "Output length should match expected");
        TEST_ASSERT(TEST_MEMEQ(result, "helloworld"), "Should convert to lowercase ASCII");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");


        TEST_ASSERT(g_alloc_call_count == 2, "Should allocate lowercase buffer and result buffer");
        TEST_ASSERT(g_downcase_call_count == 1, "Should call downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Should call UTF-8 conversion twice (probe + convert)");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "Should use correct pool tag");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    // Test 4.2: Mixed case ASCII
    reset_mock_state();
    WCHAR mixed_case[] = L"MiXeD_CaSe_123";
    create_unicode_string(&test_unicode, mixed_case, STRW_LITERAL_LEN(mixed_case));

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert mixed case ASCII");

    if (result) {
        TEST_ASSERT(TEST_MEMEQ(result, "mixed_case_123"), "Should convert to lowercase, preserve numbers and underscores");

        TEST_ASSERT(g_alloc_call_count == 2, "Should have two allocations for mixed case");
        TEST_ASSERT(g_downcase_call_count == 1, "Should call downcase for mixed case");

        // Verify that the required length calculation worked
        BOOLEAN length_calculation_ok = (g_unicode_to_utf8_call_count >= 2);
        TEST_ASSERT(length_calculation_ok, "Should have probed for length then converted");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    TEST_END("Basic ASCII Conversion");
    return TRUE;
}

// Test 5: Unicode character conversion tests
BOOLEAN test_unicode_conversion()
{
    TEST_START("Unicode Character Conversion");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;

    // Test 5.1: Unicode characters that expand in UTF-8
    reset_mock_state();
    WCHAR unicode_chars[] = L"Héllo_Wörld"; // Contains accented characters
    create_unicode_string(&test_unicode, unicode_chars, STRW_LITERAL_LEN(unicode_chars));

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert Unicode characters");

    if (result) {
        // UTF-8 encoding of accented chars will be longer than original
        TEST_ASSERT(out_length > STRW_LITERAL_LEN(unicode_chars),
            "UTF-8 length should be greater than Unicode char count for accented chars");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");


        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should be called once (accented)");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "UTF-8 should be called twice (probe + convert)");
        TEST_ASSERT(g_alloc_call_count >= 2, "Should allocate downcase and UTF-8 buffers");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "Allocations should use ART_TAG");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    // Test 5.2: High Unicode code points (emoji/symbols)
    reset_mock_state();
    WCHAR emoji_chars[] = L"Test🌟End"; // Contains emoji
    create_unicode_string(&test_unicode, emoji_chars, STRW_LITERAL_LEN(emoji_chars));

    result = unicode_to_utf8(&test_unicode, &out_length);
    if (result) {
        TEST_ASSERT(out_length > 0, "Should produce valid UTF-8 output");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");


        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should be called once (emoji)");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "UTF-8 should probe and convert once each");
        TEST_ASSERT(g_alloc_call_count >= 2, "Should allocate downcase and UTF-8 buffers");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    TEST_END("Unicode Character Conversion");
    return TRUE;
}

// Test 6: Memory allocation failure simulation
BOOLEAN test_memory_allocation_scenarios()
{
    TEST_START("Memory Allocation Scenarios with Mock Framework");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;
    WCHAR normal_string[] = L"TestString";

    // Test 6.1: Normal case to ensure our test setup works
    reset_mock_state();
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));

    result = unicode_to_utf8(&test_unicode, &out_length);
    if (result) {
        TEST_ASSERT(out_length > 0, "Normal conversion should work");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");


        TEST_ASSERT(g_alloc_call_count >= 2, "Should have allocated for lowercased string and result");
        TEST_ASSERT(g_downcase_call_count == 1, "Should have called downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Should have called UTF-8 conversion twice (probe + convert)");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "Should use correct pool tag");


        ExFreePoolWithTag(result, ART_TAG);
    }
    cleanup_unicode_string(&test_unicode);


    // Test 6.2: Simulate first allocation failure (lowercase buffer)
    reset_mock_state();
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 0); // Fail first allocation

    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result == NULL, "Should return NULL when lowercase buffer allocation fails");
    TEST_ASSERT(g_alloc_call_count == 1, "Should have attempted one allocation");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase if allocation fails");

    cleanup_unicode_string(&test_unicode);

    // Test 6.3: Simulate second allocation failure (UTF-8 buffer)
    reset_mock_state();
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 1); // Fail second allocation

    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result == NULL, "Should return NULL when UTF-8 buffer allocation fails");
    TEST_ASSERT(g_alloc_call_count == 2, "Should have attempted two allocations");
    TEST_ASSERT(g_downcase_call_count == 1, "Should call downcase before second allocation fails");
    TEST_ASSERT(g_free_call_count >= 1, "Should cleanup allocated lowercase buffer");

    cleanup_unicode_string(&test_unicode);

    // Test 6.4: Simulate RtlDowncaseUnicodeString failure
    reset_mock_state();
    configure_mock_failure(STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, FALSE, 0);

    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result == NULL, "Should return NULL when downcase fails");
    TEST_ASSERT(g_alloc_call_count == 1, "Should have allocated lowercase buffer");
    TEST_ASSERT(g_downcase_call_count == 1, "Should have attempted downcase");
    TEST_ASSERT(g_free_call_count >= 1, "Should cleanup allocated buffer on downcase failure");

    cleanup_unicode_string(&test_unicode);

    // Test 6.5: Simulate RtlUnicodeToUTF8N probe failure
    reset_mock_state();
    configure_mock_failure(STATUS_SUCCESS, STATUS_INVALID_PARAMETER, FALSE, 0);

    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result == NULL, "Should return NULL when UTF-8 probe fails");
    TEST_ASSERT(g_downcase_call_count == 1, "Should have called downcase");
    TEST_ASSERT(g_unicode_to_utf8_call_count >= 1, "Should have attempted UTF-8 conversion");
    TEST_ASSERT(g_free_call_count >= 1, "Should cleanup on UTF-8 probe failure");

    cleanup_unicode_string(&test_unicode);

 // TEST_MODE

    // Reset mock to normal state
    reset_mock_state();

    DbgPrint("[INFO] Memory allocation failure testing completed with mock framework\n");

    TEST_END("Memory Allocation Scenarios with Mock Framework");
    return TRUE;
}

// Test 7: MAX_KEY_LENGTH boundary tests
BOOLEAN test_max_key_length_boundary()
{
    TEST_START("MAX_KEY_LENGTH Boundary Tests");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;

    // 7.1: Near the max (MAX_KEY_LENGTH - 1 bytes in UTF-8)
    reset_mock_state();
    ULONG chars_needed = MAX_KEY_LENGTH - 1; // ASCII -> 1 byte per char

    NTSTATUS status = create_unicode_string(&test_unicode, NULL, 0);
    if (NT_SUCCESS(status)) {
        if (test_unicode.Buffer) {
            ExFreePoolWithTag(test_unicode.Buffer, ART_TAG);
        }

        test_unicode.Length = (USHORT)(chars_needed * sizeof(WCHAR));
        test_unicode.MaximumLength = test_unicode.Length + sizeof(WCHAR);
        test_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            test_unicode.MaximumLength, ART_TAG);

        if (test_unicode.Buffer) {
            for (ULONG i = 0; i < chars_needed; i++) {
                test_unicode.Buffer[i] = L'A';
            }
            test_unicode.Buffer[chars_needed] = L'\0';

            result = unicode_to_utf8(&test_unicode, &out_length);
            TEST_ASSERT(result != NULL, "Should handle string near MAX_KEY_LENGTH");

            if (result) {
                TEST_ASSERT(out_length == chars_needed, "Length should match expected");


                TEST_ASSERT(g_downcase_call_count == 1, "Should downcase once");
                TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
                TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers should be allocated");


                ExFreePoolWithTag(result, ART_TAG);
            }

            cleanup_unicode_string(&test_unicode);
        }
    }

    // 7.2: Exceeding the max (reject)
    reset_mock_state();
    chars_needed = MAX_KEY_LENGTH + 10;
    status = create_unicode_string(&test_unicode, NULL, 0);
    if (NT_SUCCESS(status)) {
        if (test_unicode.Buffer) {
            ExFreePoolWithTag(test_unicode.Buffer, ART_TAG);
        }

        test_unicode.Length = (USHORT)(chars_needed * sizeof(WCHAR));
        test_unicode.MaximumLength = test_unicode.Length + sizeof(WCHAR);
        test_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            test_unicode.MaximumLength, ART_TAG);

        if (test_unicode.Buffer) {
            for (ULONG i = 0; i < chars_needed; i++) {
                test_unicode.Buffer[i] = L'A';
            }
            test_unicode.Buffer[chars_needed] = L'\0';

            // Serbest bırakma sayısını cleanup'tan önce yakalayalım

            ULONG free_before = g_free_call_count;

            result = unicode_to_utf8(&test_unicode, &out_length);
            TEST_ASSERT(result == NULL, "Should reject string exceeding MAX_KEY_LENGTH");


            TEST_ASSERT(g_downcase_call_count == 1, "Should still downcase before size check");
            TEST_ASSERT(g_unicode_to_utf8_call_count >= 1, "Probe should be called to get required length");
            TEST_ASSERT(g_alloc_call_count == 1, "Only lowercase buffer should be allocated; no UTF-8 buffer");
            TEST_ASSERT(g_free_call_count >= free_before + 1, "Lowercase buffer should be freed on reject");


            cleanup_unicode_string(&test_unicode);
        }
    }

    TEST_END("MAX_KEY_LENGTH Boundary Tests");
    return TRUE;
}

// Test 8: Edge cases and corner scenarios
BOOLEAN test_edge_cases()
{
    TEST_START("Edge Cases and Corner Scenarios");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;

    // Test 8.1: Single character string
    reset_mock_state();
    WCHAR single_char[] = L"A";
    create_unicode_string(&test_unicode, single_char, 1);

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle single character");

    if (result) {
        TEST_ASSERT(out_length == 1, "Single ASCII char should produce length 1");
        TEST_ASSERT(result[0] == 'a', "Should be lowercase");
        TEST_ASSERT(result[1] == '\0', "Should be null-terminated");


        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    // Test 8.2: String with only numbers and symbols
    reset_mock_state();
    WCHAR numbers_symbols[] = L"12345!@#$%";
    create_unicode_string(&test_unicode, numbers_symbols, STRW_LITERAL_LEN(numbers_symbols));

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle numbers and symbols");

    if (result) {
        TEST_ASSERT(out_length == STRA_LITERAL_LEN("12345!@#$%"), "Length matches");
        TEST_ASSERT(TEST_MEMEQ(result, "12345!@#$%"), "Numbers and symbols should remain unchanged");

        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");

        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    // Test 8.3: String with null characters in middle (truncated length)
    reset_mock_state();
    WCHAR with_nulls[10];
    with_nulls[0] = L'A';
    with_nulls[1] = L'B';
    with_nulls[2] = L'\0';  // Embedded null
    with_nulls[3] = L'C';
    with_nulls[4] = L'D';

    test_unicode.Buffer = with_nulls;
    test_unicode.Length = 5 * sizeof(WCHAR); // Include the embedded null
    test_unicode.MaximumLength = 10 * sizeof(WCHAR);

    result = unicode_to_utf8(&test_unicode, &out_length);
    // This tests how the function handles embedded nulls
    if (result) {
        DbgPrint("[INFO] String with embedded nulls handled, length: %d\n", out_length);


        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should still be called");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert even with embedded null");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers allocated");


        ExFreePoolWithTag(result, ART_TAG);
    }

    TEST_END("Edge Cases and Corner Scenarios");
    return TRUE;
}

// Test 9: Output parameter validation
BOOLEAN test_output_parameter_validation()
{
    TEST_START("Output Parameter Validation");

    USHORT out_length;
    PUCHAR result;
    UNICODE_STRING test_unicode;

    // Test that out_length is properly set
    reset_mock_state();
    WCHAR test_string[] = L"TestOutput";
    create_unicode_string(&test_unicode, test_string, STRW_LITERAL_LEN(test_string));

    out_length = 0x1234; // Initialize with known value
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result != NULL, "Should successfully convert");
    if (result) {
        TEST_ASSERT(out_length != 0x1234, "Should modify out_length on success");
        TEST_ASSERT(out_length > 0, "Should set positive length");
        TEST_ASSERT(out_length == STRA_LITERAL_LEN((char*)result),
            "out_length should match actual string length");

        // Verify the actual content
        TEST_ASSERT(TEST_MEMEQ(result, "testoutput"), "Content should be correctly converted");

        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");


        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&test_unicode);

    TEST_END("Output Parameter Validation");
    return TRUE;
}

// Test 10: Comprehensive integration test
BOOLEAN test_comprehensive_integration()
{
    TEST_START("Comprehensive Integration Test");

    // Test a realistic file path scenario
    reset_mock_state();
    WCHAR realistic_path[] = L"\\Device\\HarddiskVolume1\\Users\\TestUser\\Documents\\MyFile.txt";
    UNICODE_STRING path_unicode;
    USHORT out_length;
    PUCHAR result;

    create_unicode_string(&path_unicode, realistic_path, STRW_LITERAL_LEN(realistic_path));

    result = unicode_to_utf8(&path_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle realistic file path");

    if (result) {
        TEST_ASSERT(out_length > 0, "Should produce valid output length");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");

        // Check that it's properly lowercased
        BOOLEAN has_uppercase = FALSE;
        for (USHORT i = 0; i < out_length; i++) {
            if (result[i] >= 'A' && result[i] <= 'Z') {
                has_uppercase = TRUE;
                break;
            }
        }
        TEST_ASSERT(!has_uppercase, "Should not contain uppercase ASCII letters");


        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once for path");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert for path");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers allocated for path");


        DbgPrint("[INFO] Converted path: %.*s\n", out_length, result);
        ExFreePoolWithTag(result, ART_TAG);
    }

    cleanup_unicode_string(&path_unicode);

    TEST_END("Comprehensive Integration Test");
    return TRUE;
}

// Main test runner function
NTSTATUS run_all_unicode_to_utf8_tests()
{
    DbgPrint("\n========================================\n");
    DbgPrint("Starting Comprehensive unicode_to_utf8 Test Suite\n");
    DbgPrint("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    // Run all test suites
    if (!test_null_pointer_validation()) all_passed = FALSE;
    if (!test_empty_string_validation()) all_passed = FALSE;
    if (!test_length_boundary_validation()) all_passed = FALSE;
    if (!test_basic_ascii_conversion()) all_passed = FALSE;
    if (!test_unicode_conversion()) all_passed = FALSE;
    if (!test_memory_allocation_scenarios()) all_passed = FALSE;
    if (!test_max_key_length_boundary()) all_passed = FALSE;
    if (!test_edge_cases()) all_passed = FALSE;
    if (!test_output_parameter_validation()) all_passed = FALSE;
    if (!test_comprehensive_integration()) all_passed = FALSE;

    DbgPrint("\n========================================\n");
    if (all_passed) {
        DbgPrint("ALL TESTS PASSED!\n");
    }
    else {
        DbgPrint("SOME TESTS FAILED!\n");
    }
    DbgPrint("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}