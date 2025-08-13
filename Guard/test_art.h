#pragma once
#include "adaptive_radix_tree.h"
#include "log.h"

//-------------------------------------------------------
// Test framework macros
//-------------------------------------------------------
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            LOG_MSG("[TEST FAILED] %s: %s\n", __FUNCTION__, message); \
            return FALSE; \
        }\
       /* else {\
            LOG_MSG("[TEST PASSED] %s: %s\n", __FUNCTION__, message); \
        }\*/\
    } while(0)

#define TEST_START(test_name) \
    LOG_MSG("\n=== Starting Test: %s ===\n", test_name)

#define TEST_END(test_name) //\
    LOG_MSG("=== Test %s Completed ===\n\n", test_name)

//-------------------------------------------------------
// Mock/Test state (extern)
//-------------------------------------------------------
extern ULONG  g_alloc_call_count;
extern ULONG  g_free_call_count;
extern ULONG  g_downcase_call_count;
extern ULONG  g_unicode_to_utf8_call_count;

extern PVOID  g_last_allocated_pointer;
extern SIZE_T g_last_allocated_size;   // <— SIZE_T (daha doğru)
extern ULONG  g_last_allocated_tag;

extern PVOID  g_last_freed_pointer;
extern ULONG  g_last_freed_tag;

extern NTSTATUS g_mock_downcase_return;
extern NTSTATUS g_mock_unicode_to_utf8_return;
extern BOOLEAN  g_simulate_alloc_failure;
extern ULONG    g_alloc_failure_after_count;

// create header
extern volatile LONG g_copy_header_fail_once_flag;
extern NTSTATUS g_copy_header_fail_status;

// free_node()
extern UCHAR   g_last_freed_node_type_before_free;

// free_leaf()
extern ULONG   g_debugbreak_count;
extern USHORT  g_last_freed_leaf_keylen_before_free;

// add_child48();
extern NTSTATUS g_mock_add_child48_once;

//-------------------------------------------------------
// Mock API prototypes (implementasyon test_art.c içinde)
// Not: Makro remap burada DEĞİL; SUT header'ında (adaptive_radix_tree.h)
// UNIT_TEST tanımlı iken yapılmalı.
//-------------------------------------------------------
PVOID Test_ExAllocatePool2(ULONG PoolFlags, SIZE_T NumberOfBytes, ULONG Tag);
VOID  Test_ExFreePool2(PVOID P, ULONG Tag, PCPOOL_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParametersCount);

NTSTATUS Test_RtlDowncaseUnicodeString(
    PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString);

NTSTATUS Test_RtlUnicodeToUTF8N(
    PCHAR UTF8StringDestination,
    ULONG UTF8StringMaxByteCount,
    PULONG UTF8StringActualByteCount,
    PCWCH UnicodeStringSource,
    ULONG UnicodeStringByteCount);

//-------------------------------------------------------
// Helpers to manage mock state
//-------------------------------------------------------
void reset_mock_state(void);
void configure_mock_failure(NTSTATUS downcase_status,
    NTSTATUS utf8_status,
    BOOLEAN alloc_fail,
    ULONG alloc_fail_after);

// --- UTF-8 fine-grained mock controls (for probe/convert separation) ---
VOID configure_mock_utf8_paths(
    _In_ NTSTATUS probe_status,
    _In_ NTSTATUS convert_status,
    _In_ ULONG force_written_length_on_convert // 0 => do not override written length
);

VOID configure_mock_utf8_probe_zero_required_length(VOID);

VOID mock_copy_header_fail_once(_In_ NTSTATUS status);
VOID mock_add_child48_fail_once(_In_ NTSTATUS status);

//-------------------------------------------------------
// CRT Helpers
//-------------------------------------------------------
#ifndef STRA_LITERAL_LEN
#define STRA_LITERAL_LEN(s) ((USHORT)(sizeof(s) - 1))                 // bytes, for char/UTF-8 literals
#endif
#ifndef STRW_LITERAL_LEN
#define STRW_LITERAL_LEN(s) ((USHORT)(RTL_NUMBER_OF(s) - 1))          // characters, for wide literals
#endif

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

//-------------------------------------------------------
// Unicode helpers
//-------------------------------------------------------
void    cleanup_unicode_string(UNICODE_STRING* str);
NTSTATUS create_unicode_string(UNICODE_STRING* dest, const WCHAR* source, ULONG length_chars);

// ===== helpers (no CRT) =====
ART_NODE* t_alloc_header_only(NODE_TYPE t);
ART_NODE4* t_alloc_node4(void);
ART_NODE16* t_alloc_node16(void);
ART_NODE48* t_alloc_node48(void);
ART_NODE256* t_alloc_node256(void);
ART_NODE* t_alloc_dummy_child(NODE_TYPE t);
VOID         t_free(void* p);
ART_NODE* test_alloc_node_base(void);
ART_LEAF* test_alloc_leaf(USHORT key_len, UCHAR start_val);
PUCHAR       t_alloc_key(USHORT len, UCHAR start);
VOID         test_free_leaf(ART_LEAF* lf);
VOID         test_free_node_all(void* p);
VOID         test_free_node_any(ART_NODE* node);

// Seed helpers
BOOLEAN t_seed_node4_sorted(ART_NODE4* n, USHORT cnt, UCHAR start);
BOOLEAN t_seed_node16_sorted(ART_NODE16* n, USHORT cnt, UCHAR start);
VOID    t_free_children4(ART_NODE4* n);
VOID    t_free_children16(ART_NODE16* n);
VOID    t_free_children48(ART_NODE48* n);
VOID    t_free_children256(ART_NODE256* n);
