#include "authorization_control.h"

#include "adaptive_radix_tree.h"
#include "global_context.h"

#include <string.h>

BOOLEAN control_path_access_right(PFLT_CALLBACK_DATA data, UINT32 access_right);
BOOLEAN find_prefixes_in_policies(PUNICODE_STRING path);

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

    BOOLEAN is_exist_in_policies = find_prefixes_in_policies(&name_info->Name);
    FltReleaseFileNameInformation(name_info);
    if (!is_exist_in_policies) {
        return TRUE;
    }

    return control_path_access_right(data, g_art_root->access_rights);
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

BOOLEAN find_prefixes_in_policies(PUNICODE_STRING path) {
    if (path == NULL || path->Length == 0 || path->Buffer == NULL) {
        return FALSE;
    }

    UNICODE_STRING prefix;
    prefix = *path;
    while (prefix.Length > 0) {
        // Search the current prefix in ART
        BOOLEAN is_found = art_search(g_art_root, &prefix);
        if (is_found) {
            return TRUE; // Found a prefix in policies
        }

        // Find the position of the last backslash before the current end
        USHORT i;
        for (i = prefix.Length / sizeof(WCHAR); i > 0; i--) {
            if (prefix.Buffer[i - 1] == L'\\') {
                // Set the new prefix length (excluding trailing part)
                prefix.Length = (i - 1) * sizeof(WCHAR);
                prefix.MaximumLength = prefix.Length;
                break;
            }
        }

        // If no backslash found, we've reached the topmost prefix
        if (i == 0) {
            break;
        }
    }

    return FALSE;
}