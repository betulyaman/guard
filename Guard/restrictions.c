#include "restrictions.h"

#include "global_context.h"

BOOLEAN is_in_restricted_path(_In_ PFLT_CALLBACK_DATA data) {
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

    UNICODE_STRING restricted_path;
    RtlInitUnicodeString(&restricted_path, g_context.agent_path);
    if (RtlPrefixUnicodeString(&restricted_path, &(name_info->Name), TRUE)) {
        FltReleaseFileNameInformation(name_info);
        return TRUE;
    }

    FltReleaseFileNameInformation(name_info);
    return FALSE;
}
