#include "preoperation_callbacks.h"

#include "authorization_control.h"
#include "communication.h"
#include "global_context.h"
#include "log.h"
#include "pending_operation_list.h"
#include "windows_service_controls.h"

ULONG g_operation_id;

BOOLEAN is_agent_connected();
BOOLEAN is_ntfs_metadata_file(PFLT_CALLBACK_DATA data);
BOOLEAN compare_unicode_strings(PUNICODE_STRING str1, PUNICODE_STRING str2);
BOOLEAN is_in_installation_path(_In_ PFLT_CALLBACK_DATA data);
BOOLEAN is_local_database_file(_In_ PFLT_CALLBACK_DATA data);

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
	UNREFERENCED_PARAMETER(completion_callback);
	UNREFERENCED_PARAMETER(filter_objects);

	if (data->RequestorMode == KernelMode) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//// Check if Agent connected for debugging !!
	//if (!is_agent_connected()) {
	//	LOG_MSG("Agent is not connected");
	//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	//}

	// Do not handle the file operations in internal NTFS system files or directories
	if (is_ntfs_metadata_file(data)) {
		LOG_MSG("NTFS system file operaitons");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	 //Check if the requester is Agent
	 //Do not block Agent
	if (FltGetRequestorProcessId(data) == (ULONG)g_context.agent_process_id) {
		LOG_MSG("The requester is Agent");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Do not block the windows services
	if (is_trusted_installer_process()) {
		LOG_MSG("The requester is WINDOWS");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Block accessing the restricted path
	if (is_in_installation_path(data)) {
		LOG_MSG("It is in a restricted path.");
		data->IoStatus.Status = STATUS_ACCESS_DENIED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	OPERATION_TYPE operation_type = get_operation_type(data, filter_objects);
	if (operation_type == OPERATION_TYPE_INVALID) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (is_local_database_file(data)) {
		LOG_MSG("Local database can't be deleted.");
		data->IoStatus.Status = STATUS_ACCESS_DENIED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	if (!is_authorized(data)) {
		data->IoStatus.Status = STATUS_ACCESS_DENIED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	//// Allow rename operations that are part of allowed write flows, while still denying malicious or unrelated renames.
	//if (operation_type == OPERATION_TYPE_RENAME) {
	//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	//}

	//MINIFILTER_REQUEST message;
	//NTSTATUS status = create_minifilter_request(data, g_operation_id, operation_type, &message, filter_objects);
	//if (!NT_SUCCESS(status)) {
	//	data->IoStatus.Status = STATUS_UNSUCCESSFUL;
	//	return FLT_PREOP_COMPLETE;
	//}

	//status = send_message_to_user(&message);
	//if (!NT_SUCCESS(status)) {
	//	data->IoStatus.Status = STATUS_UNSUCCESSFUL;
	//	return FLT_PREOP_COMPLETE;
	//}

	//status = add_operation_to_pending_list(data, g_operation_id);
	//if (!NT_SUCCESS(status)) {
	//	data->IoStatus.Status = STATUS_UNSUCCESSFUL;
	//	return FLT_PREOP_COMPLETE;
	//}

	//g_operation_id++;
	//
	//pending_operation_list_timeout_clear();

	//return FLT_PREOP_PENDING;

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN is_agent_connected() {
	return (g_context.client_port != NULL);
}

BOOLEAN is_ntfs_metadata_file(PFLT_CALLBACK_DATA data) {
	static const WCHAR* systemFiles[] = {
		L"$Mft", L"$MftMirr", L"$LogFile", L"$Volume", L"$AttrDef",
		L"$", L"$Bitmap", L"$Boot", L"$BadClus", L"$Secure",
		L"$Upcase", L"$Extend", L"$Quota", L"$ObjId", L"$Reparse", L"$RECYCLE.BIN"
	};

	PFLT_FILE_NAME_INFORMATION name_info;
	NTSTATUS status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &name_info);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	status = FltParseFileNameInformation(name_info);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	if (!name_info || name_info->Name.Length == 0 || !name_info->Name.Buffer) {
		FltReleaseFileNameInformation(name_info);
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

BOOLEAN is_in_installation_path(_In_ PFLT_CALLBACK_DATA data) {
	
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

	UNICODE_STRING installation_path;
	RtlInitUnicodeString(&installation_path, g_context.agent_installation_path);
	if (RtlPrefixUnicodeString(&installation_path, &(name_info->Name), TRUE)) {
		FltReleaseFileNameInformation(name_info);
		return TRUE;
	}

	FltReleaseFileNameInformation(name_info);
	return FALSE;
}

BOOLEAN is_local_database_file(_In_ PFLT_CALLBACK_DATA data) {
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

	UNICODE_STRING local_db_file;
	RtlInitUnicodeString(&local_db_file, g_context.local_db_path);
	if (RtlPrefixUnicodeString(&local_db_file, &(name_info->Name), TRUE)) {
		FltReleaseFileNameInformation(name_info);
		return TRUE;
	}

	FltReleaseFileNameInformation(name_info);
	return FALSE;
}