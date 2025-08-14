#if UNIT_TEST

#include "test_art.h"

// Mock fonksiyonlarının içinde “gerçek” API çağıracağız. Remap açık kalırsa Test_ExAllocatePool2  
// içinden ExAllocatePool2 dediğimiz anda yine Test_ExAllocatePool2’ye gidersonsuz döngü.
#ifdef ExAllocatePool2
#undef ExAllocatePool2
#endif
#ifdef ExFreePool2
#undef ExFreePool2
#endif
#ifdef RtlDowncaseUnicodeString
#undef RtlDowncaseUnicodeString
#endif
#ifdef RtlUnicodeToUTF8N
#undef RtlUnicodeToUTF8N
#endif

extern NTSTATUS run_all_unicode_to_utf8_tests(void);
extern NTSTATUS run_all_destroy_utf8_key_tests(void);
extern NTSTATUS run_all_free_node_tests(void);
extern NTSTATUS run_all_free_leaf_tests(void);
extern NTSTATUS run_all_art_create_node_tests(void);
extern NTSTATUS run_all_art_init_tree_tests(void);
extern NTSTATUS run_all_leaf_matches_tests(void);
extern NTSTATUS run_all_ctz_tests(void);
extern NTSTATUS run_all_find_child_tests(void);
extern NTSTATUS run_all_copy_header_tests(void);
extern NTSTATUS run_all_check_prefix_tests(void);
extern NTSTATUS run_all_minimum_tests(void);
extern NTSTATUS run_all_maximum_tests(void);
extern NTSTATUS run_all_make_leaf_tests(void);
extern NTSTATUS run_all_longest_common_prefix_tests(void);
extern NTSTATUS run_all_add_child256_tests(void);
extern NTSTATUS run_all_add_child48_tests(void);
extern NTSTATUS run_all_add_child16_tests(void);
extern NTSTATUS run_all_add_child4_tests(void);
extern NTSTATUS run_all_add_child_tests(void);
extern NTSTATUS run_all_recursive_insert_tests(void);
extern NTSTATUS run_all_art_insert_tests(void);
extern NTSTATUS run_all_art_insert_no_replace_tests(void);
extern NTSTATUS run_all_remove_child256_tests(void);
extern NTSTATUS run_all_remove_child48_tests(void);
extern NTSTATUS run_all_remove_child16_tests(void);
extern NTSTATUS run_all_remove_child4_tests(void);
extern NTSTATUS run_all_remove_child_tests(void);
extern NTSTATUS run_all_recursive_delete_internal_tests(void);
extern NTSTATUS run_all_recursive_delete_tests(void);
extern NTSTATUS run_all_art_delete_tests(void);
extern NTSTATUS run_all_recursive_delete_all_internal_tests(void);
extern NTSTATUS run_all_art_delete_subtree_tests(void);
extern NTSTATUS run_all_art_destroy_tree_tests(void);
extern NTSTATUS run_all_art_search_tests(void);
extern NTSTATUS run_all_prefix_compare_tests(void);

// ===== mock state =====
ULONG  g_alloc_call_count = 0;
ULONG  g_free_call_count = 0;
ULONG  g_downcase_call_count = 0;
ULONG  g_unicode_to_utf8_call_count = 0;

PVOID  g_last_allocated_pointer = NULL;
SIZE_T g_last_allocated_size = 0;
ULONG  g_last_allocated_tag = 0;

PVOID g_last_freed_pointer = NULL;
ULONG g_last_freed_tag = 0;

NTSTATUS g_mock_downcase_return = STATUS_SUCCESS;
NTSTATUS g_mock_unicode_to_utf8_return = STATUS_SUCCESS;
BOOLEAN g_simulate_alloc_failure = FALSE;
ULONG g_alloc_failure_after_count = 0; // fail when count > this

// --- UTF-8 fine-grained overrides for RtlUnicodeToUTF8N ---
BOOLEAN g_utf8_override_enabled = FALSE;
BOOLEAN g_utf8_probe_zero_required = FALSE;
NTSTATUS g_utf8_probe_status = STATUS_SUCCESS;
NTSTATUS g_utf8_convert_status = STATUS_SUCCESS;
ULONG g_utf8_force_written_len_on_convert = 0; // 0 => no override

// copy header
volatile LONG g_copy_header_fail_once_flag = 0;
NTSTATUS g_copy_header_fail_status = STATUS_UNSUCCESSFUL;

// free_node()
UCHAR g_last_freed_node_type_before_free = 0xEE;

// free_leaf()
ULONG g_debugbreak_count = 0;
USHORT g_last_freed_leaf_keylen_before_free = 0xEEEE;

// add_child48()
NTSTATUS g_mock_add_child48_once = STATUS_SUCCESS;

// ===== MOCK IMPLEMENTASYONLARI =====
PVOID Test_ExAllocatePool2(ULONG PoolFlags, SIZE_T NumberOfBytes, ULONG Tag)
{
    g_alloc_call_count++;

    if (g_simulate_alloc_failure && g_alloc_call_count > g_alloc_failure_after_count) {
        // LOG_MSG("[TEST MOCK] ExAllocatePool2 simulating failure (call #%lu)\n", g_alloc_call_count);
        return NULL;
    }

    // Store allocation details for verification
    g_last_allocated_size = NumberOfBytes;
    g_last_allocated_tag = Tag;

    // // Actually allocate memory for testing (remap kapalı!)
    PVOID ptr = ExAllocatePool2(PoolFlags, NumberOfBytes, Tag);
    g_last_allocated_pointer = ptr;

    // LOG_MSG("[TEST MOCK] ExAllocatePool2 called: Size=%Iu, Tag=0x%08X, Result=%p\n", (size_t)NumberOfBytes, Tag, ptr);

    return ptr;
}

VOID Test_ExFreePool2(PVOID P, ULONG Tag, PCPOOL_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParametersCount)
{
    g_free_call_count++;
    g_last_freed_pointer = P;
    g_last_freed_tag = Tag;

    // LOG_MSG("[TEST MOCK] ExFreePool2 called with P=%p, Tag=0x%08X\n", P, Tag);

    // Actually free the memory
    if (P) {
        ExFreePool2(P, Tag, ExtendedParameters, ExtendedParametersCount);
    }
}

NTSTATUS Test_RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString)
{
    g_downcase_call_count++;
    // LOG_MSG("[TEST MOCK] RtlDowncaseUnicodeString called (call #%lu)\n", g_downcase_call_count);

    if (!NT_SUCCESS(g_mock_downcase_return)) {
        // LOG_MSG("[TEST MOCK] RtlDowncaseUnicodeString returning mock failure: 0x%x\n",g_mock_downcase_return);
        return g_mock_downcase_return;
    }

    // Call real function
    return RtlDowncaseUnicodeString(DestinationString, SourceString, AllocateDestinationString);
}

NTSTATUS Test_RtlUnicodeToUTF8N(
    PCHAR UTF8StringDestination,
    ULONG UTF8StringMaxByteCount,
    PULONG UTF8StringActualByteCount,
    PCWCH UnicodeStringSource,
    ULONG UnicodeStringByteCount)
{
    g_unicode_to_utf8_call_count++;

    // Distinguish probe from convert. Probe => Destination == NULL.
    const BOOLEAN is_probe = (UTF8StringDestination == NULL);
    UNREFERENCED_PARAMETER(UnicodeStringSource);
    UNREFERENCED_PARAMETER(UnicodeStringByteCount);

    // --- Fine-grained override path for unit tests ---
    if (g_utf8_override_enabled)
    {
        if (is_probe)
        {
            if (g_utf8_probe_zero_required)
            {
                // Simulate: probe succeeds but required_length == 0
                if (UTF8StringActualByteCount)
                {
                    *UTF8StringActualByteCount = 0;
                }
                return g_utf8_probe_status; // typically STATUS_SUCCESS
            }
            else
            {
                // Normal probe override: return a positive required length (arbitrary but >0)
                if (UTF8StringActualByteCount)
                {
                    *UTF8StringActualByteCount = 32;
                }
                return g_utf8_probe_status;
            }
        }
        else
        {
            // Convert step override (may succeed or fail).
            // Tests expect we can force "SUCCESS with written_length == 0",
            // or any other specific written length (e.g., 8, 64, ...).
            if (UTF8StringActualByteCount) {
            *UTF8StringActualByteCount = g_utf8_force_written_len_on_convert; // publish exactly what tests requested
        }
                // Only write into the destination when there is a positive written length.
                if (UTF8StringDestination && UTF8StringMaxByteCount > 0) {
                if (g_utf8_force_written_len_on_convert > 0) {
                    const ULONG to_fill = UTF8StringMaxByteCount; // never overflow buffer
                    RtlFillMemory(UTF8StringDestination, to_fill, 'x');
                    UTF8StringDestination[to_fill - 1] = '\0';
                }
                else {
                    // Force "no bytes written" semantics: do not touch the buffer.
                }
            }
            return g_utf8_convert_status;
        }
    }

    // --- Legacy coarse-grained failure override (back-compat with existing tests) ---
    if (!NT_SUCCESS(g_mock_unicode_to_utf8_return))
    {
        // When a global failure is requested, honor it as-is.
        return g_mock_unicode_to_utf8_return;
    }

    // --- Default: call the real RTL function (remap is disabled above) ---
#pragma warning(push)
#pragma warning(disable: 6387)
    return RtlUnicodeToUTF8N(UTF8StringDestination, UTF8StringMaxByteCount, UTF8StringActualByteCount, UnicodeStringSource, UnicodeStringByteCount);
#pragma warning(pop)
}


// Helper function to reset mock state
void reset_mock_state(void)
{
    g_alloc_call_count = 0;
    g_free_call_count = 0;
    g_downcase_call_count = 0;
    g_unicode_to_utf8_call_count = 0;

    g_last_allocated_pointer = NULL;
    g_last_allocated_size = 0;
    g_last_allocated_tag = 0;

    g_last_freed_pointer = NULL;
    g_last_freed_tag = 0;

    g_mock_downcase_return = STATUS_SUCCESS;
    g_mock_unicode_to_utf8_return = STATUS_SUCCESS;
    g_simulate_alloc_failure = FALSE;
    g_alloc_failure_after_count = 0;

    g_last_freed_node_type_before_free = 0xEE;

    g_debugbreak_count = 0;
    g_last_freed_leaf_keylen_before_free = 0xEEEE;

    // --- Reset fine-grained UTF-8 overrides ---
    g_utf8_override_enabled = FALSE;
    g_utf8_probe_zero_required = FALSE;
    g_utf8_probe_status = STATUS_SUCCESS;
    g_utf8_convert_status = STATUS_SUCCESS;
    g_utf8_force_written_len_on_convert = 0;

    // --- Also reset one-shot copy_header failure so tests are isolated ---
    g_copy_header_fail_once_flag = 0;
    g_copy_header_fail_status = STATUS_UNSUCCESSFUL;
}

void configure_mock_failure(NTSTATUS downcase_status, NTSTATUS utf8_status, BOOLEAN alloc_fail, ULONG alloc_fail_after)
{
    g_mock_downcase_return = downcase_status;
    g_mock_unicode_to_utf8_return = utf8_status;
    g_simulate_alloc_failure = alloc_fail;
    g_alloc_failure_after_count = alloc_fail_after;
}

// Configure behavior for probe and convert phases separately.
VOID configure_mock_utf8_paths(
    _In_ NTSTATUS probe_status,
    _In_ NTSTATUS convert_status,
    _In_ ULONG force_written_length_on_convert
)
{
    g_utf8_override_enabled = TRUE;
    g_utf8_probe_zero_required = FALSE;
    g_utf8_probe_status = probe_status;
    g_utf8_convert_status = convert_status;
    g_utf8_force_written_len_on_convert = force_written_length_on_convert;
}

// Make the probe return required_length == 0 (with STATUS_SUCCESS).
VOID configure_mock_utf8_probe_zero_required_length(VOID)
{
    g_utf8_override_enabled = TRUE;
    g_utf8_probe_zero_required = TRUE;
    g_utf8_probe_status = STATUS_SUCCESS;
    g_utf8_convert_status = STATUS_UNSUCCESSFUL; // convert won't be reached by SUT in this case
    g_utf8_force_written_len_on_convert = 0;
}


VOID Test_DebugBreak(VOID)
{
    g_debugbreak_count++;
    LOG_MSG("[TEST MOCK] __debugbreak() hit\n");
}

// Helper function to cleanup Unicode string
void cleanup_unicode_string(UNICODE_STRING* str)
{
    if (str && str->Buffer) {
        ExFreePool2(str->Buffer, ART_TAG, NULL, 0);
        str->Buffer = NULL;
        str->Length = 0;
        str->MaximumLength = 0;
    }
}

NTSTATUS create_unicode_string(UNICODE_STRING* dest, const WCHAR* source, ULONG length_chars)
{
    if (!dest)
        return STATUS_INVALID_PARAMETER;

    dest->Length = (USHORT)(length_chars * sizeof(WCHAR));
    dest->MaximumLength = dest->Length + sizeof(WCHAR);

    dest->Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, dest->MaximumLength, ART_TAG);
    if (!dest->Buffer) {
        return STATUS_NO_MEMORY;
    }

    if (source && length_chars > 0) {
        RtlCopyMemory(dest->Buffer, source, dest->Length);
    }
    dest->Buffer[length_chars] = L'\0';

    return STATUS_SUCCESS;
}

VOID mock_copy_header_fail_once(_In_ NTSTATUS status)
{
    g_copy_header_fail_status = status ? status : STATUS_UNSUCCESSFUL;
    InterlockedExchange(&g_copy_header_fail_once_flag, 1);
}

VOID reset_copy_header_mock_state(VOID)
{
    g_copy_header_fail_status = STATUS_UNSUCCESSFUL;
    InterlockedExchange(&g_copy_header_fail_once_flag, 0);
}

VOID mock_add_child48_fail_once(_In_ NTSTATUS status) {
    g_mock_add_child48_once = status;
}

// ===== helpers (no CRT) =====

ART_NODE* t_alloc_header_only(NODE_TYPE t)
{
    ART_NODE* n = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->type = t;
    n->num_of_child = 0;
    n->prefix_length = 0;
    return n;
}

ART_NODE4* t_alloc_node4(void)
{
    ART_NODE4* n = (ART_NODE4*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE4), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->base.type = NODE4;
    return n;
}

ART_NODE16* t_alloc_node16(void)
{
    ART_NODE16* n = (ART_NODE16*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE16), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->base.type = NODE16;
    return n;
}

ART_NODE48* t_alloc_node48(void)
{
    ART_NODE48* n = (ART_NODE48*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE48), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->base.type = NODE48;
    return n;
}

ART_NODE256* t_alloc_node256(void)
{
    ART_NODE256* n = (ART_NODE256*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE256), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->base.type = NODE256;
    return n;
}

ART_NODE* t_alloc_dummy_child(NODE_TYPE t)
{
    ART_NODE* n = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
    if (!n) return NULL;
    RtlZeroMemory(n, sizeof(*n));
    n->type = t;
    return n;
}

ART_NODE* test_alloc_node_base(void)
{
    ART_NODE* p = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_NODE), ART_TAG);
    if (p)
        RtlZeroMemory(p, sizeof(*p));
    return p;
}

ART_LEAF* test_alloc_leaf(USHORT key_len, UCHAR start_val)
{
    SIZE_T sz = sizeof(ART_LEAF) + key_len;
    ART_LEAF* lf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, ART_TAG);
    if (!lf) return NULL;
    RtlZeroMemory(lf, sz);
    lf->value = 0xDEADBEEF;   // arbitrary
    lf->key_length = key_len;
    for (USHORT i = 0; i < key_len; ++i) {
        lf->key[i] = (UCHAR)(start_val + (UCHAR)i);
    }
    return lf;
}

PUCHAR t_alloc_key(USHORT len, UCHAR start)
{
    if (!len) return NULL;
    PUCHAR b = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, ART_TAG);
    if (!b) return NULL;
    for (USHORT i = 0; i < len; ++i) b[i] = (UCHAR)(start + (UCHAR)i);
    return b;
}

VOID t_free(void* p)
{
    if (p) ExFreePool2(p, ART_TAG, NULL, 0);
}

VOID test_free_leaf(ART_LEAF* lf)
{
    if (lf) ExFreePool2(lf, ART_TAG, NULL, 0);
}

VOID test_free_node_all(void* p)
{
    if (p) ExFreePool2(p, ART_TAG, NULL, 0);
}

VOID test_free_node_any(ART_NODE* node)
{
    if (!node) return;

    switch (node->type)
    {
    case NODE4:
        ExFreePool2((ART_NODE4*)node, ART_TAG, NULL, 0);
        break;
    case NODE16:
        ExFreePool2((ART_NODE16*)node, ART_TAG, NULL, 0);
        break;
    case NODE48:
        ExFreePool2((ART_NODE48*)node, ART_TAG, NULL, 0);
        break;
    case NODE256:
        ExFreePool2((ART_NODE256*)node, ART_TAG, NULL, 0);
        break;
    default:
        // unknown or dummy node — yine de free et
        ExFreePool2(node, ART_TAG, NULL, 0);
        break;
    }
}

// Seed helpers

BOOLEAN t_seed_node4_sorted(ART_NODE4* n, USHORT cnt, UCHAR start)
{
    if (!n || cnt > 4) return FALSE;
    n->base.num_of_child = 0;
    for (USHORT i = 0; i < cnt; i++) {
        n->keys[i] = (UCHAR)(start + (UCHAR)i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        if (!n->children[i]) {
            for (USHORT j = 0; j < i; j++) { t_free(n->children[j]); n->children[j] = NULL; }
            n->base.num_of_child = 0;
            return FALSE;
        }
        n->base.num_of_child++;
    }
    return TRUE;
}

BOOLEAN t_seed_node16_sorted(ART_NODE16* n, USHORT cnt, UCHAR start)
{
    if (!n || cnt > 16) return FALSE;
    n->base.num_of_child = 0;
    for (USHORT i = 0; i < cnt; i++) {
        n->keys[i] = (UCHAR)(start + (UCHAR)i);
        n->children[i] = t_alloc_dummy_child(NODE4);
        if (!n->children[i]) {
            for (USHORT j = 0; j < i; j++) { t_free(n->children[j]); n->children[j] = NULL; }
            n->base.num_of_child = 0;
            return FALSE;
        }
        n->base.num_of_child++;
    }
    return TRUE;
}

VOID t_free_children4(ART_NODE4* n)
{
    if (!n) return;
    for (USHORT i = 0; i < 4; i++) { if (n->children[i]) t_free(n->children[i]); n->children[i] = NULL; }
}

VOID t_free_children16(ART_NODE16* n)
{
    if (!n) return;
    for (USHORT i = 0; i < 16; i++) { if (n->children[i]) t_free(n->children[i]); n->children[i] = NULL; }
}

VOID t_free_children48(ART_NODE48* n)
{
    if (!n) return;
    for (USHORT i = 0; i < 48; i++) { if (n->children[i]) t_free(n->children[i]); n->children[i] = NULL; }
}

VOID t_free_children256(ART_NODE256* n)
{
    if (!n) return;
    for (USHORT i = 0; i < 256; i++) { if (n->children[i]) t_free(n->children[i]); n->children[i] = NULL; }
}

VOID
ArtTestDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    LOG_MSG("[ART][TEST] Unload called. Bye!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = ArtTestDriverUnload;

    LOG_MSG("\n=================================================\n");
    LOG_MSG(" ART Test Driver — starting all test suites\n");
    LOG_MSG("=================================================\n");

    BOOLEAN all_ok = TRUE;
    NTSTATUS st;

    //st = run_all_unicode_to_utf8_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_destroy_utf8_key_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_free_node_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_free_leaf_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_create_node_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_init_tree_tests();              if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_leaf_matches_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_ctz_tests();                        if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_find_child_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_copy_header_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_check_prefix_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_minimum_tests();                    if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_maximum_tests();                    if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_make_leaf_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_longest_common_prefix_tests();      if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_add_child256_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_add_child48_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_add_child16_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_add_child4_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_add_child_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_recursive_insert_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_insert_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_insert_no_replace_tests();      if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_remove_child256_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_remove_child48_tests();             if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_remove_child16_tests();             if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_remove_child4_tests();              if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_remove_child_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_recursive_delete_internal_tests();  if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_recursive_delete_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_delete_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_recursive_delete_all_internal_tests(); if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_delete_subtree_tests();         if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_art_destroy_tree_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_search_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    //st = run_all_prefix_compare_tests();             if (!NT_SUCCESS(st)) all_ok = FALSE;

    LOG_MSG("\n=================================================\n");
    if (all_ok) {
        LOG_MSG(" ART Test Driver — ALL TEST SUITES PASSED \n");
    }
    else {
        LOG_MSG(" ART Test Driver — SOME TESTS FAILED \n");
    }
    LOG_MSG("=================================================\n\n");

    return STATUS_SUCCESS;
}

#endif

FIM:
================================================ =

FIM : ART Test Driver — starting all test suites

FIM : ================================================ =

FIM :
    ========================================

    FIM : Starting remove_child() Test Suite

    FIM : ========================================


    FIM :
    == = Starting Test : remove_child: guard checks == =

    FIM :
    == = Starting Test : remove_child: NODE4 requires leaf == =

    FIM : free_leaf : freeing leaf at FFFFCA88C0B8F770
    FIM : free_leaf: freeing leaf at FFFFCA88C0B8F470
    FIM :
== = Starting Test : remove_child: NODE16 requires leaf == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F6D0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F3D0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F270
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F570
FIM :
== = Starting Test : remove_child: NODE48 dispatch success == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F150
FIM :
== = Starting Test : remove_child: NODE256 dispatch success == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F350
FIM :
== = Starting Test : remove_child: NODE48 NOT_FOUND path == =

FIM : [ART] remove_child48 : Key 50 not present

FIM : free_leaf: freeing leaf at FFFFCA88C0B8F2D0
FIM :
== = Starting Test : remove_child: NODE256 NOT_FOUND path == =

FIM : [ART] remove_child256 : Child at index 161 does not exist

FIM : free_leaf: freeing leaf at FFFFCA88C0B8F1F0
FIM :
== = Starting Test : remove_child: NODE4 dispatch success(2->collapse) == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F890
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F7D0
FIM :
== = Starting Test : remove_child: NODE16 dispatch success == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F510
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F4F0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F6F0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F370
FIM :
== = Starting Test : remove_child: invalid node type == =

FIM :
    == = Starting Test : remove_child: NODE48 rejects non - NULL leaf param == =

    FIM : free_leaf : freeing leaf at FFFFCA88C0B8F830
    FIM : [ART] [WARN] double free attempt for leaf FFFFCA88C0B8F830

    FIM : [TEST MOCK] __debugbreak() hit

    FIM : free_leaf: freeing leaf at FFFFCA88C0B8F830
    FIM :
== = Starting Test : remove_child: NODE256 rejects non - NULL leaf param == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F690
FIM : [ART] [WARN] double free attempt for leaf FFFFCA88C0B8F690

FIM : [TEST MOCK] __debugbreak() hit

FIM : free_leaf: freeing leaf at FFFFCA88C0B8F690
FIM :
== = Starting Test : remove_child: NODE4 with leaf pointer but * leaf == NULL == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F7F0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F250
FIM :
== = Starting Test : remove_child: NODE16 with leaf pointer but * leaf == NULL == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F610
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F730
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F130
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F870
FIM :
== = Starting Test : remove_child: NODE4 wrong slot pointer == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F4B0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F4D0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F410
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F0B0
FIM :
== = Starting Test : remove_child: NODE16 wrong slot pointer == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F5D0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F2B0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F430
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F650
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F850
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F450
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F810
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F550
FIM :
========================================

FIM : ALL remove_child() TESTS PASSED!

FIM : ========================================


FIM :
    ========================================

    FIM : Starting art_delete_subtree() Test Suite

    FIM : ========================================


    FIM :
    == = Starting Test : art_delete_subtree: guard params == =

    FIM :
    == = Starting Test : art_delete_subtree: empty tree == =

    FIM : [ART] Tree is empty
    FIM :
== = Starting Test : art_delete_subtree: empty prefix key == =

FIM :
    == = Starting Test : art_delete_subtree: prefix not found(missing child) == =

    FIM : destroy_utf8_key : freeing UTF - 8 key at FFFFCA88C0B8F210
    FIM : free_leaf: freeing leaf at FFFFCA88C0B8F790
    FIM :
== = Starting Test : art_delete_subtree: prefix mismatch(node prefix) == =

FIM : destroy_utf8_key : freeing UTF - 8 key at FFFFCA88C0B8F290
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F630
FIM :
== = Starting Test : art_delete_subtree: delete exact leaf == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8F3B0
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FB10
FIM :
== = Starting Test : art_delete_subtree: delete internal subtree(NODE4 parent) == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B90030
FIM : free_leaf: freeing leaf at FFFFCA88C0B8F990
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8F9B0


FIM :
    == = Starting Test : art_delete_subtree: delete internal subtree(NODE256 parent) == =

    FIM : free_leaf : freeing leaf at FFFFCA88C0B8FAD0
    FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FC30
    FIM : free_leaf: freeing leaf at FFFFCA88C0B8FA70
    FIM :
== = Starting Test : art_delete_subtree: fallback succeeds on deep overflow == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FA30
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B90070
FIM :
== = Starting Test : art_delete_subtree[EX] : long prefix partial match at ROOT -> delete whole subtree == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FF10
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FE10
FIM :
== = Starting Test : art_delete_subtree[EX] : delete subtree under NODE16 parent == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FF70
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FED0
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FFF0
FIM :
== = Starting Test : art_delete_subtree[EX] : delete subtree under NODE48 parent == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FC90
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FAF0
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8F9F0


FIM :
== = Starting Test : art_delete_subtree[EX] : oversize prefix rejected, tree unchanged == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FBF0
FIM :
========================================

FIM : SOME art_delete_subtree() TESTS FAILED!

FIM : ========================================


FIM :
    ========================================

    FIM : Starting art_search() Test Suite

    FIM : ========================================


    FIM :
    == = Starting Test : art_search: guard params == =

    FIM :
    == = Starting Test : art_search: empty tree == =

    FIM : [ART] Search on empty tree
    FIM :
== = Starting Test : art_search: unicode_to_utf8 failure == =

FIM : unicode_to_utf8 : key length 4097 exceeds limits(MAX_KEY_LENGTH = 4096, MAXUSHORT = 65535)
FIM : [ART] Failed to convert Unicode key
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FA90
FIM :
== = Starting Test : art_search: empty key after conversion == =

FIM : [ART] Failed to convert Unicode key
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FAB0
FIM :
== = Starting Test : art_search: exact match(leaf root) == =

FIM : destroy_utf8_key : freeing UTF - 8 key at FFFFCA88C0B8FD70
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FFB0
FIM :
== = Starting Test : art_search: NODE4 path == =

FIM : free_leaf : freeing leaf at FFFFCA88C0B8FBB0
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8F9D0
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FFD0
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B90050
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FE90
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FDF0
FIM :
== = Starting Test : art_search: prefix handling == =

FIM : destroy_utf8_key : freeing UTF - 8 key at FFFFCA88C0B8FC70
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B8FB70
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C0B90170
FIM : free_leaf: freeing leaf at FFFFCA88C0B8FD10
FIM :
== = Starting Test : art_search: NODE48 & NODE256 == =

FIM : destroy_utf8_key : freeing UTF - 8 key at FFFFCA88C0B90590


FIM :
== = Starting Test : art_search: recursion depth overflow guard == =

FIM : [ART] Search aborted due to depth guard
FIM : destroy_utf8_key: freeing UTF - 8 key at FFFFCA88C54E2F30
KDTARGET : Refreshing KD connection

* **Fatal System Error : 0x0000007f
(0x0000000000000008, 0xFFFF9780B29F6E70, 0xFFFFF50C36BC0FC0, 0xFFFFF8004ECD3829)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

For analysis of this file, run !analyze - v
nt!DbgBreakPointWithStatus:
fffff800`b9cffa20 cc              int     3
