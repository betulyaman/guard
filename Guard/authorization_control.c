#include "authorization_control.h"

#include "adaptive_radix_tree.h"
#include "global_context.h"

#include <string.h>

ART_NODE* g_art_node;

BOOLEAN control_path_access_right(PFLT_CALLBACK_DATA data, UINT32 access_right);
BOOLEAN find_prefixes_in_policies(PUNICODE_STRING path, PUINT32 access_right);

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

    UINT32 access_right;
    BOOLEAN is_exist_in_policies = find_prefixes_in_policies(&name_info->Name, &access_right);
    FltReleaseFileNameInformation(name_info);
    
    if (!is_exist_in_policies) {
        return TRUE;
    }

    return control_path_access_right(data, access_right);
}

BOOLEAN control_path_access_right(PFLT_CALLBACK_DATA data, UINT32 access_right) {
    switch (data->Iopb->MajorFunction) {
    case IRP_MJ_READ:
        return (access_right & POLICY_MASK_READ) != 0;

    case IRP_MJ_WRITE:
        return (access_right & (POLICY_MASK_READ | POLICY_MASK_WRITE)) != 0;

    case IRP_MJ_CREATE: {
        ACCESS_MASK desired_access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        if ((desired_access & FILE_READ_DATA) && (access_right & POLICY_MASK_READ)) {
            return TRUE;
        }
        if ((desired_access & FILE_WRITE_DATA) && (access_right & (POLICY_MASK_READ | POLICY_MASK_WRITE))) {
            return TRUE;
        }
        if ((desired_access & FILE_EXECUTE) && (access_right & (POLICY_MASK_READ | POLICY_MASK_WRITE))) {
            return TRUE;
        }
        return FALSE;
    }

    case IRP_MJ_SET_INFORMATION:
        return (access_right & (POLICY_MASK_READ | POLICY_MASK_WRITE)) != 0;

    default:
        return FALSE;
    }
}

BOOLEAN find_prefixes_in_policies(PUNICODE_STRING path, PUINT32 out_access_right) {
    if (!path || path->Length == 0 || !path->Buffer || !out_access_right) {
        return FALSE;
    }

    UNICODE_STRING prefix = *path;

    while (prefix.Length > 0) {
        ACCESS_MASK access_right;

        if (art_search(g_art_node, &prefix, &access_right)) {
            *out_access_right = access_right;
            return TRUE;
        }

        USHORT i;
        // Trim one level from the end (go up one directory)
        for (i = prefix.Length / sizeof(WCHAR); i > 0; i--) {
            if (prefix.Buffer[i - 1] == L'\\') {
                prefix.Length = (i - 1) * sizeof(WCHAR);
                break;
            }
        }

        if (i == 0) {
            break;
        }
    }

    return FALSE;
}