#include "communication.h"

#include "global_context.h"
#include "log.h"
#include "pending_operation_list.h"

#include <ntstrsafe.h>

NTSTATUS get_file_name(_Inout_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING file_name);
LONG exception_handler(_In_ PEXCEPTION_POINTERS ExceptionPointer, _In_ BOOLEAN AccessingUserBuffer);


NTSTATUS connect_notify_callback(
	_In_ PFLT_PORT client_port,
	_In_ PVOID server_port_cookie,
	_In_reads_bytes_(size_of_context) PVOID connection_context,
	_In_ ULONG size_of_context,
	_Outptr_result_maybenull_ PVOID* connection_cookie)
{
	UNREFERENCED_PARAMETER(server_port_cookie);
	UNREFERENCED_PARAMETER(connection_context);
	UNREFERENCED_PARAMETER(size_of_context);
	*connection_cookie = NULL;

	FLT_ASSERT(g_context.client_port == NULL);

    const ULONG expected_token = 0xA5A5A5A5;
    
    if (size_of_context != sizeof(USER_PROCESS_INFO)) {
        return STATUS_ACCESS_DENIED;
    }

    USER_PROCESS_INFO context;
    RtlCopyMemory(&context, connection_context, size_of_context);
    if (context.token != expected_token) {
        return STATUS_ACCESS_DENIED;
    }

    g_context.agent_process_id = context.process_id;

    RtlCopyMemory(g_context.agent_path, context.path, sizeof(context.path));

	g_context.client_port = client_port;
	return STATUS_SUCCESS;
}

VOID disconnect_notify_callback(
	_In_opt_ PVOID connection_cookie)
{
	UNREFERENCED_PARAMETER(connection_cookie);

	if (g_context.client_port != NULL)
	{
		FltCloseClientPort(g_context.registered_filter, &g_context.client_port);
		g_context.client_port = NULL;
	}
}

NTSTATUS create_communication_port()
{
	PSECURITY_DESCRIPTOR security_descriptor = NULL;
	NTSTATUS status = FltBuildDefaultSecurityDescriptor(&security_descriptor, FLT_PORT_ALL_ACCESS);
	if (NT_ERROR(status)) {
		LOG_MSG("FltBuildDefaultSecurityDescriptor failed. status 0x%x\n", status);
		return status;
	}

	UNICODE_STRING portName;
	RtlInitUnicodeString(&portName, COMMUNICATION_PORT_NAME);

	OBJECT_ATTRIBUTES object_attributes;
	InitializeObjectAttributes(&object_attributes,
		&portName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		security_descriptor);

	status = FltCreateCommunicationPort(g_context.registered_filter,
		&g_context.server_port,
		&object_attributes,
		NULL,
		connect_notify_callback,
		disconnect_notify_callback,
        user_reply_notify_callback,
		1);

	FltFreeSecurityDescriptor(security_descriptor);

	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(g_context.registered_filter);
	}

	return status;
}

// called whenever a user mode application wishes to communicate with the minifilter.
NTSTATUS user_reply_notify_callback(
    _In_ PVOID port_cookie,
    _In_reads_bytes_opt_(input_buffer_length) PVOID input_buffer,
    _In_ ULONG input_buffer_length,
    _Out_writes_bytes_to_opt_(output_buffer_length, *return_output_buffer_length) PVOID output_buffer,
    _In_ ULONG output_buffer_length,
    _Out_ PULONG return_output_buffer_length
) {
    UNREFERENCED_PARAMETER(port_cookie);
    UNREFERENCED_PARAMETER(output_buffer);
    UNREFERENCED_PARAMETER(output_buffer_length);
    *return_output_buffer_length = 0;

    if ((input_buffer == NULL) ||
        (input_buffer_length < (FIELD_OFFSET(USER_REPLY, operation_id) +
            sizeof(USER_REPLY)))) {
        return STATUS_INVALID_PARAMETER;
    }

    USER_REPLY reply;
    try {
        reply.operation_id = ((USER_REPLY*)input_buffer)->operation_id;
        reply.allow = ((USER_REPLY*)input_buffer)->allow;
    } except(exception_handler(GetExceptionInformation(), TRUE)) {

        return GetExceptionCode();
    }

    PENDING_OPERATION* replied_operation = pending_operation_list_remove_by_id(reply.operation_id);
    if (replied_operation == NULL) {
        // TODO replied operation doesnt exist in the pending list
        return STATUS_UNSUCCESSFUL;
    }

    if (reply.allow == TRUE) {
        replied_operation->data->IoStatus.Status = STATUS_SUCCESS;
        FltCompletePendedPreOperation(replied_operation->data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
    }
    else {
        replied_operation->data->IoStatus.Status = STATUS_ACCESS_DENIED;
        replied_operation->data->IoStatus.Information = 0;
        FltCompletePendedPreOperation(replied_operation->data, FLT_PREOP_COMPLETE, NULL);

    }

    ExFreePoolWithTag(replied_operation, PENDING_OPERATION_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS create_confirmation_message(_In_ PFLT_CALLBACK_DATA data, _In_ ULONG operation_id, _In_ OPERATION_TYPE operation_type, _Out_ CONFIRMATION_MESSAGE* message, PCFLT_RELATED_OBJECTS filter_objects) {

    if (message == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    message->operation_id = operation_id;
    message->operation_type = operation_type;

    if (operation_type == OPERATION_TYPE_RENAME || operation_type == OPERATION_TYPE_MOVE) {

        PFILE_RENAME_INFORMATION rename_info = (PFILE_RENAME_INFORMATION)data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (rename_info && rename_info->FileNameLength > 0) {

            PFLT_FILE_NAME_INFORMATION source_name_info = NULL;
            PFLT_FILE_NAME_INFORMATION dest_name_info = NULL;

            // Get current (source) file name
            NTSTATUS status = FltGetFileNameInformation(data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                &source_name_info);
            if (NT_SUCCESS(status)) {
                FltParseFileNameInformation(source_name_info);

                // Get destination (target) file name info
                status = FltGetDestinationFileNameInformation(
                    filter_objects->Instance,
                    filter_objects->FileObject,
                    rename_info->RootDirectory,
                    rename_info->FileName,
                    rename_info->FileNameLength,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                    &dest_name_info);

                if (dest_name_info->Name.Length > 0 && dest_name_info->Name.Length < sizeof(message->target_name)) {
                    RtlCopyMemory(
                        message->target_name,
                        dest_name_info->Name.Buffer,
                        dest_name_info->Name.Length
                    );
                    message->target_name[dest_name_info->Name.Length / sizeof(WCHAR)] = L'\0';
                }

                FltReleaseFileNameInformation(source_name_info);
            }
        }
    }
    else {
        WCHAR buffer[MAX_FILE_NAME_LENGTH] = { 0 };
        NTSTATUS status = RtlStringCchCopyW(message->target_name, 260, buffer);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    WCHAR buffer[MAX_FILE_NAME_LENGTH];
    UNICODE_STRING file_name = { .Length = 0, .MaximumLength = MAX_FILE_NAME_LENGTH, .Buffer = buffer };
    NTSTATUS status = get_file_name(data, &file_name);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = RtlStringCchCopyW(message->file_name, 260, file_name.Buffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS send_message_to_user(_In_ CONFIRMATION_MESSAGE* message)
{
    if (g_context.client_port == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (message == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = FltSendMessage(
        g_context.registered_filter,
        &g_context.client_port,
        message,
        sizeof(CONFIRMATION_MESSAGE),
        NULL,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

OPERATION_TYPE get_operation_type(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS filter_objects)
{
    OPERATION_TYPE operation_type = OPERATION_TYPE_INVALID;

    if (data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ULONG createOptions = data->Iopb->Parameters.Create.Options;

        if ((createOptions & FILE_DELETE_ON_CLOSE) == FILE_DELETE_ON_CLOSE) {
            operation_type = OPERATION_TYPE_FILE_ON_CLOSE;
        }
    }
    else {
        FILE_INFORMATION_CLASS file_information_class = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (file_information_class == FileDispositionInformation ||
            file_information_class == FileDispositionInformationEx) {

            PFILE_DISPOSITION_INFORMATION file_information = (PFILE_DISPOSITION_INFORMATION)data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (file_information->DeleteFile) {
                operation_type = OPERATION_TYPE_DELETE;
            }
        }
        else if (file_information_class == FileRenameInformation || file_information_class == FileRenameInformationEx) {

            PFILE_RENAME_INFORMATION rename_info = (PFILE_RENAME_INFORMATION)data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (rename_info && rename_info->FileNameLength > 0) {

                PFLT_FILE_NAME_INFORMATION source_name_info = NULL;
                PFLT_FILE_NAME_INFORMATION dest_name_info = NULL;

                // Get current (source) file name
                NTSTATUS status = FltGetFileNameInformation(data,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                    &source_name_info);
                if (NT_SUCCESS(status)) {
                    FltParseFileNameInformation(source_name_info);

                    // Get destination (target) file name info
                    status = FltGetDestinationFileNameInformation(
                        filter_objects->Instance,
                        filter_objects->FileObject,
                        rename_info->RootDirectory,
                        rename_info->FileName,
                        rename_info->FileNameLength,
                        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                        &dest_name_info);

                    if (NT_SUCCESS(status)) {
                        FltParseFileNameInformation(dest_name_info);

                        // Compare directories
                        if (RtlEqualUnicodeString(&source_name_info->ParentDir, &dest_name_info->ParentDir, TRUE)) {
                            operation_type = OPERATION_TYPE_RENAME;
                        }
                        else {
                            operation_type = OPERATION_TYPE_MOVE;
                        }

                        FltReleaseFileNameInformation(dest_name_info);
                    }

                    FltReleaseFileNameInformation(source_name_info);
                }
            }
        }
    }
    return operation_type;
}

NTSTATUS get_file_name(_Inout_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING file_name) {
    if (file_name == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PFLT_FILE_NAME_INFORMATION name_info;
    NTSTATUS status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED, &name_info);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(name_info);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name_info);
        return status;
    }

    status = RtlUnicodeStringCopy(file_name, &name_info->Name);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name_info);
        return status;
    }

    FltReleaseFileNameInformation(name_info);

    return status;
}


LONG exception_handler(
    _In_ PEXCEPTION_POINTERS ExceptionPointer,
    _In_ BOOLEAN AccessingUserBuffer)
{
    NTSTATUS Status;

    Status = ExceptionPointer->ExceptionRecord->ExceptionCode;

    //  Certain exceptions shouldn't be dismissed within the filter
    //  unless we're touching user memory.

    if (!FsRtlIsNtstatusExpected(Status) &&
        !AccessingUserBuffer) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_EXECUTE_HANDLER;
}
