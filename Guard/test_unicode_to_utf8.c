#include <ntifs.h>
#include <ntstrsafe.h>
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

    // SUT ölçümü için sayaçları temizle
    reset_mock_state();

    // Test 1.1: NULL unicode parameter
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
    reset_mock_state();
#pragma warning(push)
#pragma warning(disable: 6387)
    result = unicode_to_utf8(&valid_unicode, NULL);
#pragma warning(pop)
    TEST_ASSERT(result == NULL, "Should return NULL for NULL out_length parameter");
    TEST_ASSERT(g_alloc_call_count == 0, "Should not allocate memory for NULL out_length");
    TEST_ASSERT(g_downcase_call_count == 0, "Should not call downcase for NULL out_length");
    TEST_ASSERT(g_unicode_to_utf8_call_count == 0, "Should not call UTF-8 conversion for NULL out_length");

    // Test 1.3/1.4: NULL Buffer in unicode string
    UNICODE_STRING null_buffer_unicode = { 0 };
    null_buffer_unicode.Length = 10;
    null_buffer_unicode.MaximumLength = 20;
    null_buffer_unicode.Buffer = NULL;

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

    create_unicode_string(&empty_unicode, empty_buffer, 0);
    empty_unicode.Length = 0; // Explicitly set to 0

    // SUT ölçümü için sayaçları temizle
    reset_mock_state();

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

// ================================
// Test 3: Length boundary tests
// ================================
BOOLEAN test_length_boundary_validation()
{
    TEST_START("Length Boundary Validation");

    USHORT out_length = 0;
    PUCHAR result = NULL;
    UNICODE_STRING u = { 0 };

    // 3.1: Sınırda başarı (ASCII -> UTF-8 byte sayısı tam MAX_KEY_LENGTH)
    reset_mock_state();

    const ULONG max_wchars_with_nul = (MAXUSHORT / sizeof(WCHAR)) - 1; // NUL için 1 wchar ayır
    ULONG boundary_chars = (ULONG)MAX_KEY_LENGTH; // ASCII için UTF-8 bytes == wchar sayısı
    if (boundary_chars > max_wchars_with_nul) {
        boundary_chars = max_wchars_with_nul;
    }

    u.Length = (USHORT)(boundary_chars * sizeof(WCHAR));
    const SIZE_T alloc = ((SIZE_T)boundary_chars + 1) * sizeof(WCHAR); // +1 wchar for NUL
    u.MaximumLength = (USHORT)alloc;
    u.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc, ART_TAG);
    TEST_ASSERT(u.Buffer != NULL, "3.1-pre: boundary buffer alloc");

    for (ULONG i = 0; i < boundary_chars; ++i) u.Buffer[i] = L'A';
    u.Buffer[boundary_chars] = L'\0';

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count, d0 = g_downcase_call_count, c0 = g_unicode_to_utf8_call_count;

    result = unicode_to_utf8(&u, &out_length);

    TEST_ASSERT(result != NULL, "Should succeed at ASCII boundary (<= MAX_KEY_LENGTH)");
    TEST_ASSERT(out_length == (USHORT)boundary_chars, "UTF-8 length should equal ASCII char count");
    TEST_ASSERT(g_downcase_call_count - d0 == 1, "Should downcase once at boundary");
    TEST_ASSERT(g_unicode_to_utf8_call_count - c0 == 2, "Probe + convert on success");
    TEST_ASSERT(g_alloc_call_count - a0 >= 2, "Lowercase + UTF-8 buffers should be allocated");

    if (result) ExFreePool2(result, ART_TAG, NULL, 0);
    if (u.Buffer) ExFreePool2(u.Buffer, ART_TAG, NULL, 0);

    // 3.2: Geçersiz UNICODE_STRING.Length (tek bayt) -> NULL dönmeli ve sızıntı olmamalı
    reset_mock_state();
    UNICODE_STRING bad = { 0 };
    WCHAR tmp3[3] = { L'A', L'B', L'\0' };
    bad.Buffer = tmp3;
    bad.Length = 3;                     // bilerek tek bayt
    bad.MaximumLength = sizeof(tmp3);

    a0 = g_alloc_call_count; f0 = g_free_call_count; d0 = g_downcase_call_count; c0 = g_unicode_to_utf8_call_count;

    result = unicode_to_utf8(&bad, &out_length);
    TEST_ASSERT(result == NULL, "Should reject invalid UNICODE_STRING.Length (not even)");

    // SUT içerisinde tahsis olmuş olabilir; önemli olan sızıntı olmaması
    TEST_ASSERT((g_free_call_count - f0) >= (g_alloc_call_count - a0), "No leaks on early reject");

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

    // 4.1: Simple ASCII
    reset_mock_state();
    WCHAR simple_ascii[] = L"HelloWorld";
    create_unicode_string(&test_unicode, simple_ascii, STRW_LITERAL_LEN(simple_ascii));

    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert simple ASCII");
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length == (USHORT)actual_len, "Output length should match actual");
        TEST_ASSERT(TEST_MEMEQ(result, "helloworld"), "Should convert to lowercase ASCII");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");
        TEST_ASSERT(g_alloc_call_count == 2, "Should allocate lowercase buffer and result buffer");
        TEST_ASSERT(g_downcase_call_count == 1, "Should call downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Should call UTF-8 conversion twice (probe + convert)");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "Should use correct pool tag");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }
    cleanup_unicode_string(&test_unicode);

    // 4.2: Mixed case ASCII
    reset_mock_state();
    WCHAR mixed_case[] = L"MiXeD_CaSe_123";
    create_unicode_string(&test_unicode, mixed_case, STRW_LITERAL_LEN(mixed_case));

    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert mixed case ASCII");
    if (result) {
        TEST_ASSERT(TEST_MEMEQ(result, "mixed_case_123"), "Should convert to lowercase, preserve numbers and underscores");
        TEST_ASSERT(g_alloc_call_count == 2, "Should have two allocations for mixed case");
        TEST_ASSERT(g_downcase_call_count == 1, "Should call downcase for mixed case");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Should have probed for length then converted");
        ExFreePool2(result, ART_TAG, NULL, 0);
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

    // 5.1: Accented
    reset_mock_state();
    WCHAR unicode_chars[] = L"Héllo_Wörld";
    create_unicode_string(&test_unicode, unicode_chars, STRW_LITERAL_LEN(unicode_chars));

    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should successfully convert Unicode characters");
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length == (USHORT)actual_len, "UTF-8 length should match byte count");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should be called once (accented)");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "UTF-8 should be called twice (probe + convert)");
        TEST_ASSERT(g_alloc_call_count >= 2, "Should allocate downcase and UTF-8 buffers");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "Allocations should use ART_TAG");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }
    cleanup_unicode_string(&test_unicode);

    // 5.2: Emoji
    reset_mock_state();
    WCHAR emoji_chars[] = L"Test🌟End";
    create_unicode_string(&test_unicode, emoji_chars, STRW_LITERAL_LEN(emoji_chars));

    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length == (USHORT)actual_len, "Should produce valid UTF-8 output");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should be called once (emoji)");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "UTF-8 should probe and convert once each");
        TEST_ASSERT(g_alloc_call_count >= 2, "Should allocate downcase and UTF-8 buffers");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }
    cleanup_unicode_string(&test_unicode);

    TEST_END("Unicode Character Conversion");
    return TRUE;
}

// ===============================================
// Test 6: Memory allocation failure simulation
// ===============================================
BOOLEAN test_memory_allocation_scenarios()
{
    TEST_START("Memory Allocation Scenarios with Mock Framework");

    USHORT out_length = 0;
    PUCHAR result = NULL;
    UNICODE_STRING test_unicode;

    // 6.1: Normal akış (kontrol)
    reset_mock_state();
    WCHAR normal_string[] = L"TestString";
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));

    ULONG a0 = g_alloc_call_count, f0 = g_free_call_count, d0 = g_downcase_call_count, c0 = g_unicode_to_utf8_call_count;

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Normal conversion should work");
    TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");
    TEST_ASSERT(g_downcase_call_count - d0 == 1, "Should have called downcase once");
    TEST_ASSERT(g_unicode_to_utf8_call_count - c0 == 2, "Should have called UTF-8 conversion twice");
    TEST_ASSERT(g_alloc_call_count - a0 >= 2, "Lowercase + UTF-8 buffers");

    if (result) ExFreePool2(result, ART_TAG, NULL, 0);
    cleanup_unicode_string(&test_unicode);

    // 6.2: İlk tahsis (lowercase buffer) fail
    reset_mock_state();
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string)); // hazırlık önce
    a0 = g_alloc_call_count; f0 = g_free_call_count; d0 = g_downcase_call_count; c0 = g_unicode_to_utf8_call_count;

    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 0); // sonraki ilk ExAllocatePool2 (SUT'ta) fail

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL when lowercase buffer allocation fails");
    TEST_ASSERT(g_alloc_call_count - a0 == 1, "Exactly one SUT allocation attempt (lowercase)");
    TEST_ASSERT(g_downcase_call_count - d0 == 0, "Downcase must not be called if lowercase allocation fails");

    cleanup_unicode_string(&test_unicode);

    // 6.3: İkinci tahsis (UTF-8 buffer) fail
    reset_mock_state();
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    a0 = g_alloc_call_count; f0 = g_free_call_count; d0 = g_downcase_call_count; c0 = g_unicode_to_utf8_call_count;

    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 1); // ilk SUT alloc OK, ikincisi fail

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL when UTF-8 buffer allocation fails");
    TEST_ASSERT(g_alloc_call_count - a0 == 2, "Two SUT allocations attempted");
    TEST_ASSERT(g_downcase_call_count - d0 == 1, "Downcase should have run");
    TEST_ASSERT(g_free_call_count - f0 >= 1, "Lowercase buffer must be freed on failure");
    cleanup_unicode_string(&test_unicode);

    // 6.4: RtlDowncaseUnicodeString failure
    reset_mock_state();
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    a0 = g_alloc_call_count; f0 = g_free_call_count; d0 = g_downcase_call_count;

    configure_mock_failure(STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, FALSE, 0);

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL when downcase fails");
    TEST_ASSERT(g_alloc_call_count - a0 == 1, "Lowercase buffer allocated before downcase");
    TEST_ASSERT(g_downcase_call_count - d0 == 1, "Downcase attempted");
    TEST_ASSERT(g_free_call_count - f0 >= 1, "Lowercase buffer freed on failure");
    cleanup_unicode_string(&test_unicode);

    // 6.5: RtlUnicodeToUTF8N probe failure
    reset_mock_state();
    create_unicode_string(&test_unicode, normal_string, STRW_LITERAL_LEN(normal_string));
    a0 = g_alloc_call_count; f0 = g_free_call_count; d0 = g_downcase_call_count; c0 = g_unicode_to_utf8_call_count;

    configure_mock_failure(STATUS_SUCCESS, STATUS_INVALID_PARAMETER, FALSE, 0);

    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result == NULL, "Should return NULL when UTF-8 probe fails");
    TEST_ASSERT(g_downcase_call_count - d0 == 1, "Downcase should be called");
    TEST_ASSERT(g_unicode_to_utf8_call_count - c0 >= 1, "UTF-8 probe attempted");
    TEST_ASSERT(g_free_call_count - f0 >= 1, "Cleanup on probe failure");
    cleanup_unicode_string(&test_unicode);

    LOG_MSG("[INFO] Memory allocation failure testing completed with mock framework\n");
    TEST_END("Memory Allocation Scenarios with Mock Framework");
    return TRUE;
}

// =====================================
// Test 7: MAX_KEY_LENGTH boundary tests
// =====================================
BOOLEAN test_max_key_length_boundary()
{
    TEST_START("MAX_KEY_LENGTH Boundary Tests");

    USHORT out_length = 0;
    PUCHAR result = NULL;

    // ---------- 7.1: Accept near-limit ASCII (fits both USHORT and MAX_KEY_LENGTH) ----------
    // We must respect two independent limits:
    //  - UNICODE_STRING.Length is USHORT (bytes), so wchar count is capped by USHORT/2
    //  - UTF-8 output length must be <= min(MAX_KEY_LENGTH, MAXUSHORT)
    // For ASCII, UTF-8 bytes == wchar count. Also we need 1 wchar for trailing NUL.
    {
        reset_mock_state();

        const ULONG max_wchars_with_nul = (MAXUSHORT / sizeof(WCHAR)) - 1; // e.g. 32766
        ULONG target_utf8_bytes = (MAX_KEY_LENGTH > 0) ? (MAX_KEY_LENGTH - 1) : 0;
        if (target_utf8_bytes > max_wchars_with_nul) {
            target_utf8_bytes = max_wchars_with_nul; // cap so Length+NUL fits into USHORT
        }

        UNICODE_STRING u;
        RtlZeroMemory(&u, sizeof(u));

        // Length in bytes; MaximumLength must include space for trailing NUL (one WCHAR)
        u.Length = (USHORT)(target_utf8_bytes * sizeof(WCHAR));
        const SIZE_T alloc_bytes = ((SIZE_T)target_utf8_bytes + 1) * sizeof(WCHAR);
        u.MaximumLength = (USHORT)alloc_bytes;

        u.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_bytes, ART_TAG);
        TEST_ASSERT(u.Buffer != NULL, "7.1-pre: input buffer alloc");

        if (u.Buffer) {
            for (ULONG i = 0; i < target_utf8_bytes; ++i) u.Buffer[i] = L'A';
            u.Buffer[target_utf8_bytes] = L'\0';
        }

        const ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        const ULONG d0 = g_downcase_call_count, c0 = g_unicode_to_utf8_call_count;

        result = unicode_to_utf8(&u, &out_length);

        TEST_ASSERT(result != NULL, "Should handle string near MAX_KEY_LENGTH (ASCII)");
        if (result) {
            TEST_ASSERT(out_length == (USHORT)target_utf8_bytes, "Length should match expected (ASCII)");
            TEST_ASSERT(g_downcase_call_count - d0 == 1, "Should downcase once");
            TEST_ASSERT(g_unicode_to_utf8_call_count - c0 == 2, "Probe + convert");
            TEST_ASSERT(g_alloc_call_count - a0 >= 2, "Lowercase + UTF-8 buffers should be allocated");
            ExFreePool2(result, ART_TAG, NULL, 0);
        }
        if (u.Buffer) ExFreePool2(u.Buffer, ART_TAG, NULL, 0);
        UNREFERENCED_PARAMETER(f0); // kept for symmetry; alloc/free counts already checked
    }

    // ---------- 7.2: Reject when UTF-8 bytes would exceed limits ----------
    // Use a code point that encodes to 3 UTF-8 bytes per single WCHAR (e.g., U+0800).
    // This lets us exceed MAX_KEY_LENGTH (and/or MAXUSHORT) without violating USHORT Length.
    {
        reset_mock_state();

        const WCHAR three_byte_wc = (WCHAR)0x0800; // 3 UTF-8 bytes, 1 WCHAR in UTF-16
        const ULONG utf8_per_char = 3;

        const ULONG max_wchars_with_nul = (MAXUSHORT / sizeof(WCHAR)) - 1; // ensures room for NUL
        // Pick a count that forces required_length > MAX_KEY_LENGTH (and likely > MAXUSHORT)
        ULONG chars = (MAX_KEY_LENGTH / utf8_per_char) + 10;
        if (chars > max_wchars_with_nul) chars = max_wchars_with_nul;

        const SIZE_T alloc_bytes = ((SIZE_T)chars + 1) * sizeof(WCHAR);

        UNICODE_STRING u2;
        RtlZeroMemory(&u2, sizeof(u2));
        u2.Length = (USHORT)(chars * sizeof(WCHAR));
        u2.MaximumLength = (USHORT)alloc_bytes;
        u2.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_bytes, ART_TAG);
        TEST_ASSERT(u2.Buffer != NULL, "7.2-pre: input buffer alloc (multi-byte)");
        if (u2.Buffer) {
            for (ULONG i = 0; i < chars; ++i) u2.Buffer[i] = three_byte_wc;
            u2.Buffer[chars] = L'\0';
        }

        const ULONG a0 = g_alloc_call_count, f0 = g_free_call_count;
        const ULONG d0 = g_downcase_call_count, c0 = g_unicode_to_utf8_call_count;

        result = unicode_to_utf8(&u2, &out_length);

        // Compute the theoretical UTF-8 size to decide expected outcome.
        const ULONG expected_bytes = chars * utf8_per_char;
        const BOOLEAN should_reject = (expected_bytes > MAX_KEY_LENGTH) || (expected_bytes > MAXUSHORT);

        if (should_reject) {
            TEST_ASSERT(result == NULL, "Should reject string exceeding MAX_KEY_LENGTH/MAXUSHORT  (multi-byte)");
            TEST_ASSERT(g_downcase_call_count - d0 == 1, "Should still downcase before size check");
            TEST_ASSERT(g_unicode_to_utf8_call_count - c0 >= 1, "Probe should be called to get required length");
            TEST_ASSERT(g_alloc_call_count - a0 == 1, "Only lowercase buffer should be allocated on reject");
            TEST_ASSERT(g_free_call_count - f0 >= 1, "Lowercase buffer should be freed on reject");
        }
        else {
            // If limits cannot be exceeded due to configuration, we still validate sane success path.
            TEST_ASSERT(result != NULL, "Should succeed when not actually exceeding limits");
            if (result) {
                ExFreePool2(result, ART_TAG, NULL, 0);
            }
        }

        if (u2.Buffer) ExFreePool2(u2.Buffer, ART_TAG, NULL, 0);
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

    // 8.1: Single character
    reset_mock_state();
    WCHAR single_char[] = L"A";
    create_unicode_string(&test_unicode, single_char, 1);
    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle single character");
    if (result) {
        TEST_ASSERT(out_length == 1, "Single ASCII char should produce length 1");
        TEST_ASSERT(result[0] == 'a', "Should be lowercase");
        TEST_ASSERT(result[1] == '\0', "Should be null-terminated");
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }
    cleanup_unicode_string(&test_unicode);

    // 8.2: Numbers and symbols
    reset_mock_state();
    WCHAR numbers_symbols[] = L"12345!@#$%";
    create_unicode_string(&test_unicode, numbers_symbols, STRW_LITERAL_LEN(numbers_symbols));
    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle numbers and symbols");
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length == (USHORT)actual_len, "Length matches");
        TEST_ASSERT(TEST_MEMEQ(result, "12345!@#$%"), "Numbers and symbols should remain unchanged");
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }
    cleanup_unicode_string(&test_unicode);

    // 8.3: Embedded NULs (explicit length)
    reset_mock_state();
    WCHAR with_nulls[10];
    with_nulls[0] = L'A';
    with_nulls[1] = L'B';
    with_nulls[2] = L'\0';
    with_nulls[3] = L'C';
    with_nulls[4] = L'D';

    test_unicode.Buffer = with_nulls;
    test_unicode.Length = 5 * sizeof(WCHAR);
    test_unicode.MaximumLength = (USHORT)sizeof(with_nulls);

    reset_mock_state();
    result = unicode_to_utf8(&test_unicode, &out_length);
    if (result) {
        LOG_MSG("[INFO] String with embedded nulls handled, length: %d\n", out_length);
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase should still be called");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert even with embedded null");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers allocated");
        ExFreePool2(result, ART_TAG, NULL, 0);
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

    reset_mock_state();
    WCHAR test_string[] = L"TestOutput";
    create_unicode_string(&test_unicode, test_string, STRW_LITERAL_LEN(test_string));

    reset_mock_state();
    out_length = 0x1234;
    result = unicode_to_utf8(&test_unicode, &out_length);

    TEST_ASSERT(result != NULL, "Should successfully convert");
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length != 0x1234, "Should modify out_length on success");
        TEST_ASSERT(out_length > 0, "Should set positive length");
        TEST_ASSERT(out_length == (USHORT)actual_len, "out_length should match actual string length");
        TEST_ASSERT(TEST_MEMEQ(result, "testoutput"), "Content should be correctly converted");
        TEST_ASSERT(g_downcase_call_count == 1, "Downcase once");
        TEST_ASSERT(g_unicode_to_utf8_call_count == 2, "Probe + convert");
        TEST_ASSERT(g_alloc_call_count >= 2, "Lowercase + UTF-8 buffers");
        ExFreePool2(result, ART_TAG, NULL, 0);
    }

    cleanup_unicode_string(&test_unicode);

    TEST_END("Output Parameter Validation");
    return TRUE;
}

// Test 10: Comprehensive integration test
BOOLEAN test_comprehensive_integration()
{
    TEST_START("Comprehensive Integration Test");

    reset_mock_state();
    WCHAR realistic_path[] = L"\\Device\\HarddiskVolume1\\Users\\TestUser\\Documents\\MyFile.txt";
    UNICODE_STRING path_unicode;
    USHORT out_length;
    PUCHAR result;

    create_unicode_string(&path_unicode, realistic_path, STRW_LITERAL_LEN(realistic_path));

    reset_mock_state();
    result = unicode_to_utf8(&path_unicode, &out_length);
    TEST_ASSERT(result != NULL, "Should handle realistic file path");
    if (result) {
        size_t actual_len = 0;
        NTSTATUS ls = RtlStringCbLengthA((char*)result, MAX_KEY_LENGTH + 1, &actual_len);
        TEST_ASSERT(NT_SUCCESS(ls), "RtlStringCbLengthA should succeed");
        TEST_ASSERT(out_length == (USHORT)actual_len, "Should produce valid output length");
        TEST_ASSERT(result[out_length] == '\0', "Should be null-terminated");

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

        LOG_MSG("[INFO] Converted path: %.*s\n", out_length, result);
        ExFreePool2(result, ART_TAG, NULL, 0);
    }

    cleanup_unicode_string(&path_unicode);

    TEST_END("Comprehensive Integration Test");
    return TRUE;
}

// Main test runner function
NTSTATUS run_all_unicode_to_utf8_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting Comprehensive unicode_to_utf8 Test Suite\n");
    LOG_MSG("========================================\n\n");

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

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}