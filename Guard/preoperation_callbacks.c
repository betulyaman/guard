#include "preoperation_callbacks.h"

#include "authorization_control.h"
#include "communication.h"
#include "global_context.h"
#include "log.h"
#include "pending_operation_list.h"
#include "windows_service_controls.h"

ULONG g_operation_id;

BOOLEAN is_agent_connected();
BOOLEAN is_ntfs_metadata_file(_In_ PFLT_FILE_NAME_INFORMATION name_info);
BOOLEAN compare_unicode_strings(PUNICODE_STRING str1, PUNICODE_STRING str2);
BOOLEAN is_in_installation_path(_In_ PFLT_FILE_NAME_INFORMATION name_info);
BOOLEAN is_local_database_file(_In_ PFLT_FILE_NAME_INFORMATION name_info);

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS filter_objects,
    _Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
    UNREFERENCED_PARAMETER(completion_callback);
    UNREFERENCED_PARAMETER(filter_objects);

    // 1. Skip kernel mode requests.
    if (data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Quick check: is the agent connected? If not, let all pass.
    if (!is_agent_connected()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get normalized file name information
    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    NTSTATUS status = FltGetFileNameInformation( 
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &name_info);
    if (!NT_SUCCESS(status) || name_info == NULL) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    status = FltParseFileNameInformation(name_info);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3. Skip NTFS metadata files (e.g. $Mft, $LogFile).
    if (is_ntfs_metadata_file(name_info)) {
        LOG_MSG("Skipping NTFS metadata file operation.");
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 4. Skip requests from the agent process.
    if (FltGetRequestorProcessId(data) == (ULONG)g_context.agent_process_id) {
        LOG_MSG("Request from agent process, skipping.");
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 5. Skip trusted Windows service processes.
    if (is_trusted_installer_process()) {
        LOG_MSG("Request from trusted Windows service, skipping.");
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Identify operation type.
    OPERATION_TYPE operation_type = get_operation_type(data, filter_objects);
    if (operation_type == OPERATION_TYPE_INVALID) {
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 6. Block access to restricted installation path for non-agent.
    if (is_in_installation_path(name_info)) {
        LOG_MSG("Access denied: restricted installation path.");
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    // 7. Block deletion of local database files.
    if (is_local_database_file(name_info)) {
        LOG_MSG("Blocking deletion of local database file.");
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    // 8. Check authorization for the file access.
    if (!is_authorized(data, name_info)) {
        LOG_MSG("Access denied: unauthorized access attempt.");
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(name_info);
        return FLT_PREOP_COMPLETE;
    }

    // All checks passed, allow operation.
    FltReleaseFileNameInformation(name_info);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN is_agent_connected() {
	return (g_context.client_port != NULL);
}

BOOLEAN is_ntfs_metadata_file(_In_ PFLT_FILE_NAME_INFORMATION name_info)
{
    static const WCHAR* systemFiles[] = {
        L"$Mft", L"$MftMirr", L"$LogFile", L"$Volume", L"$AttrDef",
        L"$", L"$Bitmap", L"$Boot", L"$BadClus", L"$Secure",
        L"$Upcase", L"$Extend", L"$Quota", L"$ObjId", L"$Reparse",
        L"$RECYCLE.BIN"
    };

    if (!name_info || name_info->Name.Length == 0 || !name_info->Name.Buffer) {
        return FALSE;
    }

    for (int i = 0; i < ARRAYSIZE(systemFiles); i++) {
        UNICODE_STRING target;
        RtlInitUnicodeString(&target, systemFiles[i]);

        if (compare_unicode_strings(&target, &name_info->FinalComponent)) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN compare_unicode_strings(PUNICODE_STRING str1, PUNICODE_STRING str2) {
    if (!str1 || !str2) {
        return FALSE;
    }

    if (str1->Length != str2->Length) {
        return FALSE;
    }

    SIZE_T result = RtlCompareMemory(str1->Buffer, str2->Buffer, str1->Length);
    return ( result == str1->Length);
}

BOOLEAN is_in_installation_path(_In_ PFLT_FILE_NAME_INFORMATION name_info)
{
    if (!name_info) {
        return FALSE;
    }

    UNICODE_STRING installation_path;
    RtlInitUnicodeString(&installation_path, g_context.agent_installation_path);
    return RtlPrefixUnicodeString(&installation_path, &name_info->Name, TRUE);
}

BOOLEAN is_local_database_file(_In_ PFLT_FILE_NAME_INFORMATION name_info)
{
    if (!name_info) {
        return FALSE;
    }

    UNICODE_STRING local_db_file;
    RtlInitUnicodeString(&local_db_file, g_context.local_db_path);
    return RtlPrefixUnicodeString(&local_db_file, &name_info->Name, TRUE);
}