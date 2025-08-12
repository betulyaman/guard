#include "test_art.h"

// Mock fonksiyonlarının içinde “gerçek” API çağıracağız. Remap açık kalırsa Test_ExAllocatePool2  
// içinden ExAllocatePool2 dediğimiz anda yine Test_ExAllocatePool2’ye gider → sonsuz döngü.
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
extern NTSTATUS run_all_prefix_mismatch_tests(void);
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
extern NTSTATUS run_all_recursive_delete_all_tests(void);
extern NTSTATUS run_all_art_delete_subtree_tests(void);
extern NTSTATUS run_all_art_destroy_tree_tests(void);
extern NTSTATUS run_all_art_search_tests(void);

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

// free_node()
UCHAR g_last_freed_node_type_before_free = 0xEE;

// free_leaf()
ULONG g_debugbreak_count = 0;
USHORT g_last_freed_leaf_keylen_before_free = 0xEEEE;

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

NTSTATUS Test_RtlUnicodeToUTF8N(PCHAR UTF8StringDestination,
    ULONG UTF8StringMaxByteCount,
    PULONG UTF8StringActualByteCount,
    PCWCH UnicodeStringSource,
    ULONG UnicodeStringByteCount)
{
    g_unicode_to_utf8_call_count++;
    // LOG_MSG("[TEST MOCK] RtlUnicodeToUTF8N called (call #%lu)\n", g_unicode_to_utf8_call_count);

    if (!NT_SUCCESS(g_mock_unicode_to_utf8_return)) {
        // LOG_MSG("[TEST MOCK] RtlUnicodeToUTF8N returning mock failure: 0x%x\n", g_mock_unicode_to_utf8_return);
        return g_mock_unicode_to_utf8_return;
    }

    // Call real function
    return RtlUnicodeToUTF8N(UTF8StringDestination,
        UTF8StringMaxByteCount,
        UTF8StringActualByteCount,
        UnicodeStringSource,
        UnicodeStringByteCount);
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
}

void configure_mock_failure(NTSTATUS downcase_status, NTSTATUS utf8_status, BOOLEAN alloc_fail, ULONG alloc_fail_after)
{
    g_mock_downcase_return = downcase_status;
    g_mock_unicode_to_utf8_return = utf8_status;
    g_simulate_alloc_failure = alloc_fail;
    g_alloc_failure_after_count = alloc_fail_after;
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

// ===== unload =====
VOID
ArtTestDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    LOG_MSG("[ART][TEST] Unload called. Bye!\n");
}

// ===== entry =====
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = ArtTestDriverUnload;

    LOG_MSG("\n=================================================\n");
    LOG_MSG(" ART Test Driver — starting all test suites\n");
    LOG_MSG("=================================================\n");

    BOOLEAN all_ok = TRUE;
    NTSTATUS st;

    st = run_all_unicode_to_utf8_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_destroy_utf8_key_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_free_node_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_free_leaf_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_create_node_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_init_tree_tests();              if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_leaf_matches_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_ctz_tests();                        if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_find_child_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_copy_header_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_check_prefix_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_minimum_tests();                    if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_maximum_tests();                    if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_make_leaf_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_longest_common_prefix_tests();      if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_prefix_mismatch_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_add_child256_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_add_child48_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_add_child16_tests();                if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_add_child4_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_add_child_tests();                  if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_recursive_insert_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_insert_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_insert_no_replace_tests();      if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_remove_child256_tests();            if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_remove_child48_tests();             if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_remove_child16_tests();             if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_remove_child4_tests();              if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_remove_child_tests();               if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_recursive_delete_internal_tests();  if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_recursive_delete_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_delete_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_recursive_delete_all_tests();       if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_delete_subtree_tests();         if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_destroy_tree_tests();           if (!NT_SUCCESS(st)) all_ok = FALSE;
    st = run_all_art_search_tests();                 if (!NT_SUCCESS(st)) all_ok = FALSE;

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
