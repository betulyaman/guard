#include "authorization_control.h"

#include "adaptive_radix_tree.h"
#include "global_context.h"

#include <string.h>

ART_NODE* g_art_node;

BOOLEAN is_access_allowed(PFLT_CALLBACK_DATA data, UINT32 access_right);
ULONG get_access_rights(PUNICODE_STRING path);

BOOLEAN is_authorized(_In_ PFLT_CALLBACK_DATA data, _In_ PFLT_FILE_NAME_INFORMATION name_info)
{
    if (!name_info) {
        return FALSE;
    }

    ULONG access_right = get_access_rights(&name_info->Name);

    // No policy defined, allow
    if (access_right == POLICY_NONE) {
        return TRUE;
    }
    return is_access_allowed(data, access_right);
}

BOOLEAN is_access_allowed(PFLT_CALLBACK_DATA data, UINT32 access_right) {
    // check operation and access right
    if (!data || !data->Iopb) {
        return FALSE;
    }

    ACCESS_MASK desired_access = 0;
    if (data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desired_access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    switch (data->Iopb->MajorFunction) {

    case IRP_MJ_READ:
        return (access_right & POLICY_MASK_READ) != 0;

    case IRP_MJ_WRITE:
        return (access_right & POLICY_MASK_WRITE) != 0;

    case IRP_MJ_CREATE: {
        if ((desired_access & FILE_READ_DATA) && (access_right & POLICY_MASK_READ)) {
            return TRUE;
        }
        if ((desired_access & FILE_WRITE_DATA) && (access_right & POLICY_MASK_WRITE)) {
            return TRUE;
        }
        if ((desired_access & FILE_EXECUTE) && (access_right & POLICY_MASK_EXECUTE)) {
            return TRUE;
        }
        return FALSE;
    }

    case IRP_MJ_SET_INFORMATION:
        return (access_right & DELETE) != 0;

    default:
        return FALSE;
    }
}

/**
 * Returns:
 * - POLICY_NONE if the item was not found,
 * - otherwise the access right is returned.
 */
ULONG get_access_rights(PUNICODE_STRING path) {
    if (!path || path->Length == 0 || !path->Buffer) {
        return FALSE;
    }

    ULONG access_right = POLICY_NONE;
    UNICODE_STRING prefix = *path;

    while (prefix.Length > 0) {

        access_right = art_search(&g_art_tree, &prefix);
        if (access_right != POLICY_NONE) {
            return access_right;
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

    return access_right;
}