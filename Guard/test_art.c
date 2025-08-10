#include "test_art.h"

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


ULONG g_alloc_call_count = 0;
ULONG g_free_call_count = 0;
ULONG g_downcase_call_count = 0;
ULONG g_unicode_to_utf8_call_count = 0;

PVOID g_last_allocated_pointer = NULL;
ULONG g_last_allocated_size = 0;
ULONG g_last_allocated_tag = 0;

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

PVOID Test_ExAllocatePool2(ULONG PoolFlags, SIZE_T NumberOfBytes, ULONG Tag)
{
    g_alloc_call_count++;

    // Simulate allocation failure if requested
    if (g_simulate_alloc_failure && g_alloc_call_count > g_alloc_failure_after_count) {
        DbgPrint("[TEST MOCK] ExAllocatePool2 simulating failure (call #%lu)\n", g_alloc_call_count);
        return NULL;
    }

    // Store allocation details for verification
    g_last_allocated_size = (ULONG)NumberOfBytes;
    g_last_allocated_tag = Tag;

    // Actually allocate memory for testing
    PVOID ptr = ExAllocatePool2(PoolFlags, NumberOfBytes, Tag);
    g_last_allocated_pointer = ptr;

    DbgPrint("[TEST MOCK] ExAllocatePool2 called: Size=%lu, Tag=0x%x, Result=%p\n",
        (ULONG)NumberOfBytes, Tag, ptr);

    return ptr;
}

VOID Test_ExFreePoolWithTag(PVOID P, ULONG Tag)
{
    g_free_call_count++;
    g_last_freed_pointer = P;
    g_last_freed_tag = Tag;

    if (P) {
        __try {
            // existing: capture node->type
            g_last_freed_node_type_before_free = ((ART_NODE*)P)->type;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_last_freed_node_type_before_free = 0xEE;
        }
        
        __try {
            // NEW: capture leaf->key_length
            g_last_freed_leaf_keylen_before_free = ((ART_LEAF*)P)->key_length;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_last_freed_leaf_keylen_before_free = 0xEEEE;
        }
    }

    DbgPrint("[TEST MOCK] ExFreePoolWithTag called with P=%p, Tag=0x%x\n", P, Tag);

    // Actually free the memory
    if (P) {
        ExFreePoolWithTag(P, Tag);
    }
}

NTSTATUS Test_RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString)
{
    g_downcase_call_count++;

    DbgPrint("[TEST MOCK] RtlDowncaseUnicodeString called (call #%lu)\n", g_downcase_call_count);

    // Return mock status if configured
    if (!NT_SUCCESS(g_mock_downcase_return)) {
        DbgPrint("[TEST MOCK] RtlDowncaseUnicodeString returning mock failure: 0x%x\n",
            g_mock_downcase_return);
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

    DbgPrint("[TEST MOCK] RtlUnicodeToUTF8N called (call #%lu)\n", g_unicode_to_utf8_call_count);

    // Return mock status if configured
    if (!NT_SUCCESS(g_mock_unicode_to_utf8_return)) {
        DbgPrint("[TEST MOCK] RtlUnicodeToUTF8N returning mock failure: 0x%x\n",
            g_mock_unicode_to_utf8_return);
        return g_mock_unicode_to_utf8_return;
    }

    // Call real function
    return RtlUnicodeToUTF8N(UTF8StringDestination, UTF8StringMaxByteCount,
        UTF8StringActualByteCount, UnicodeStringSource,
        UnicodeStringByteCount);
}

// Helper function to reset mock state
void reset_mock_state()
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
    DbgPrint("[TEST MOCK] __debugbreak() hit\n"); 
}

// Helper function to cleanup Unicode string
void cleanup_unicode_string(UNICODE_STRING* str)
{
    if (str->Buffer) {
        ExFreePoolWithTag(str->Buffer, ART_TAG);
        str->Buffer = NULL;
        str->Length = 0;
        str->MaximumLength = 0;
    }
}

// Helper function to create Unicode string from wide string
NTSTATUS create_unicode_string(UNICODE_STRING* dest, const WCHAR* source, ULONG length_chars)
{
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
ART_NODE* test_alloc_node_base(void) {
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

VOID t_free(void* p) { if (p) ExFreePoolWithTag(p, ART_TAG); }

VOID test_free_leaf(ART_LEAF* lf)
{
    if (lf) ExFreePoolWithTag(lf, ART_TAG);
}

VOID test_free_node_all(void* p)
{
    if (p) ExFreePoolWithTag(p, ART_TAG);
}

VOID test_free_node_any(ART_NODE* node)
{
    if (!node) return;

    switch (node->type)
    {
    case NODE4:
        ExFreePoolWithTag((ART_NODE4*)node, ART_TAG);
        break;
    case NODE16:
        ExFreePoolWithTag((ART_NODE16*)node, ART_TAG);
        break;
    case NODE48:
        ExFreePoolWithTag((ART_NODE48*)node, ART_TAG);
        break;
    case NODE256:
        ExFreePoolWithTag((ART_NODE256*)node, ART_TAG);
        break;
    default:
        // unknown or dummy node — yine de free et
        ExFreePoolWithTag(node, ART_TAG);
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
    DbgPrint("[ART][TEST] Unload called. Bye!\n");
}

// ===== entry =====
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = ArtTestDriverUnload;

    DbgPrint("\n=================================================\n");
    DbgPrint(" ART Test Driver — starting all test suites\n");
    DbgPrint("=================================================\n");

    BOOLEAN all_ok = TRUE;
    NTSTATUS st;

    // ---- call every suite; keep going even if one fails ----
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

    DbgPrint("\n=================================================\n");
    if (all_ok) {
        DbgPrint(" ART Test Driver — ALL TEST SUITES PASSED \n");
    }
    else {
        DbgPrint(" ART Test Driver — SOME TESTS FAILED \n");
    }
    DbgPrint("=================================================\n\n");

    // Typically return success so the driver loads even if tests failed,
    // letting you inspect logs and unload manually.
    return STATUS_SUCCESS;
}


