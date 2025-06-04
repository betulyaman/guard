#include "authorization_control.h"

#include "global_context.h"
#include "policy_engine.h"

BOOLEAN control_path_access_right(PFLT_CALLBACK_DATA data, UINT32 access_right);

BOOLEAN is_authorized(_In_ PFLT_CALLBACK_DATA data) {
    PFLT_FILE_NAME_INFORMATION name_info;
    NTSTATUS status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &name_info);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = FltParseFileNameInformation(name_info);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name_info);
        return FALSE;
    }

    TRIE_NODE* result = NULL;
    BOOLEAN is_exist = trie_search(g_trie_root, &name_info->Name, (UINT8)name_info->Name.Length, &result);
    if (!is_exist) {
        FltReleaseFileNameInformation(name_info);
        return TRUE;
    }

    return control_path_access_right(data, result->access_rights);
}

BOOLEAN control_path_access_right(PFLT_CALLBACK_DATA data, UINT32 access_right) {
    if ((access_right & MASK_READ_ONLY) 
        && (data->Iopb->MajorFunction == OPERATION_TYPE_READ)) {
        return TRUE;
    }

    if ((access_right & MASK_READ_WRITE) 
        && ((data->Iopb->MajorFunction == OPERATION_TYPE_READ)
         || (data->Iopb->MajorFunction == OPERATION_TYPE_WRITE) 
         || (data->Iopb->MajorFunction == OPERATION_TYPE_CREATE))) {
        return TRUE;
    }

    if (access_right & MASK_FULL_ACCESS) {
        return TRUE;
    }

    return FALSE;
}