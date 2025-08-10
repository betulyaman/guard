#include "adaptive_radix_tree.h"

//-------------------------------------------------------
// Test framework macros
//-------------------------------------------------------
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            DbgPrint("[TEST FAILED] %s: %s\n", __FUNCTION__, message); \
            return FALSE; \
        } else { \
            DbgPrint("[TEST PASSED] %s: %s\n", __FUNCTION__, message); \
        } \
    } while(0)

#define TEST_START(test_name) \
    DbgPrint("\n=== Starting Test: %s ===\n", test_name)

#define TEST_END(test_name) \
    DbgPrint("=== Test %s Completed ===\n\n", test_name)

//-------------------------------------------------------
// Mock/Test
//-------------------------------------------------------
extern ULONG g_alloc_call_count;
extern ULONG g_free_call_count;
extern ULONG g_downcase_call_count;
extern ULONG g_unicode_to_utf8_call_count;

extern PVOID g_last_allocated_pointer;
extern ULONG g_last_allocated_size;
extern ULONG g_last_allocated_tag;

extern PVOID g_last_freed_pointer;
extern ULONG g_last_freed_tag;

extern NTSTATUS g_mock_downcase_return;
extern NTSTATUS g_mock_unicode_to_utf8_return;
extern BOOLEAN g_simulate_alloc_failure;
extern ULONG g_alloc_failure_after_count;

// free_node()
extern UCHAR g_last_freed_node_type_before_free;

// free_leaf()
extern ULONG g_debugbreak_count;
extern USHORT g_last_freed_leaf_keylen_before_free;

// Mock function to track ExAllocatePool2 and ExFreePoolWithTag calls
// Note: In real testing, this would require hooking or test frameworks
// that can intercept kernel API calls
PVOID Test_ExAllocatePool2(ULONG PoolFlags, SIZE_T NumberOfBytes, ULONG Tag);

VOID Test_ExFreePoolWithTag(PVOID P, ULONG Tag);

NTSTATUS Test_RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString);

NTSTATUS Test_RtlUnicodeToUTF8N(PCHAR UTF8StringDestination,
    ULONG UTF8StringMaxByteCount,
    PULONG UTF8StringActualByteCount,
    PCWCH UnicodeStringSource,
    ULONG UnicodeStringByteCount);

// Replace kernel APIs with mock versions
#define ExAllocatePool2 Test_ExAllocatePool2
#define ExFreePoolWithTag Test_ExFreePoolWithTag
#define RtlDowncaseUnicodeString Test_RtlDowncaseUnicodeString
#define RtlUnicodeToUTF8N Test_RtlUnicodeToUTF8N


// Helper function to reset mock state
void reset_mock_state();
void configure_mock_failure(NTSTATUS downcase_status, NTSTATUS utf8_status, BOOLEAN alloc_fail, ULONG alloc_fail_after);

//-------------------------------------------------------
// CRT Helpers
//-------------------------------------------------------

// lengths for literals
#ifndef STRA_LITERAL_LEN
#define STRA_LITERAL_LEN(s) ((USHORT)(sizeof(s) - 1))                 // bytes, for char/UTF-8 literals
#endif
#ifndef STRW_LITERAL_LEN
#define STRW_LITERAL_LEN(s) ((USHORT)(RTL_NUMBER_OF(s) - 1))          // characters, for wide literals
#endif

// byte-compare
#ifndef TEST_MEMEQ
#define TEST_MEMEQ(buf, lit) \
    (RtlCompareMemory((buf), (lit), STRA_LITERAL_LEN(lit)) == STRA_LITERAL_LEN(lit))
#endif

//-------------------------------------------------------
// Debug Break
//-------------------------------------------------------
VOID Test_DebugBreak(VOID);
#undef __debugbreak
#define __debugbreak() Test_DebugBreak()

void cleanup_unicode_string(UNICODE_STRING* str);
NTSTATUS create_unicode_string(UNICODE_STRING * dest, const WCHAR * source, ULONG length_chars);

// ===== helpers (no CRT) =====
ART_NODE* t_alloc_header_only(NODE_TYPE t);
ART_NODE4* t_alloc_node4(void);
ART_NODE16* t_alloc_node16(void);
ART_NODE48* t_alloc_node48(void);
ART_NODE256* t_alloc_node256(void);
ART_NODE* t_alloc_dummy_child(NODE_TYPE t);
VOID t_free(void* p);
ART_NODE* test_alloc_node_base(void);
ART_LEAF* test_alloc_leaf(USHORT key_len, UCHAR start_val);
PUCHAR t_alloc_key(USHORT len, UCHAR start);
VOID test_free_leaf(ART_LEAF* lf);
VOID test_free_node_all(void* p);
VOID test_free_node_any(ART_NODE* node);

// Seed helpers
BOOLEAN t_seed_node4_sorted(ART_NODE4* n, USHORT cnt, UCHAR start);
BOOLEAN t_seed_node16_sorted(ART_NODE16* n, USHORT cnt, UCHAR start);
VOID t_free_children4(ART_NODE4* n);
VOID t_free_children16(ART_NODE16* n);
VOID t_free_children48(ART_NODE48* n);
VOID t_free_children256(ART_NODE256* n);