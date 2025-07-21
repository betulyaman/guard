#include "communication.h"

#include "adaptive_radix_tree.h"
#include "global_context.h"
#include "log.h"
#include "pending_operation_list.h"
#include "policy_manager.h"
#include "security.h"

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

    g_context.connection_state = CONNECTION_UNAUTHENTICATED;

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
	RtlInitUnicodeStringEx(&portName, COMMUNICATION_PORT_NAME);

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
        message_notify_callback,
		1);

	FltFreeSecurityDescriptor(security_descriptor);

	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(g_context.registered_filter);
	}

	return status;
}

// called whenever a user mode application wishes to communicate with the minifilter.
NTSTATUS message_notify_callback(
    _In_ PVOID port_cookie,
    _In_reads_bytes_opt_(input_buffer_length) PVOID input_buffer,
    _In_ ULONG input_buffer_length,
    _Out_writes_bytes_to_opt_(output_buffer_length, *return_output_buffer_length) PVOID output_buffer,
    _In_ ULONG output_buffer_length,
    _Out_ PULONG return_output_buffer_length
) {
    UNREFERENCED_PARAMETER(port_cookie);

    switch (g_context.connection_state) {
        case CONNECTION_UNAUTHENTICATED:
        {
            if (!output_buffer || !output_buffer_length) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = generate_secure_nonce(g_context.nonce, NONCE_SIZE);
            if (!NT_SUCCESS(status)) {
                return STATUS_UNSUCCESSFUL;
            }
            
            try {
                ProbeForRead(input_buffer, sizeof(NONCE_SIZE), sizeof(UCHAR));
                RtlCopyMemory(output_buffer, g_context.nonce, NONCE_SIZE);
                *return_output_buffer_length = NONCE_SIZE;
            } except(exception_handler(GetExceptionInformation(), TRUE)) {
                return GetExceptionCode();
            }

            g_context.connection_state = CONNECTION_AUTHENTICATING;


            DbgPrint("Connection authenticating.\n");
            return STATUS_SUCCESS;
        }
        break;

        case CONNECTION_AUTHENTICATING:
        {
            if (!input_buffer || input_buffer_length < sizeof(USER_HMAC_SIGNATURE)) {
                return STATUS_INVALID_PARAMETER;
            }

            USER_HMAC_SIGNATURE user_hmac_signature;
            try {
                ProbeForRead(input_buffer, sizeof(USER_HMAC_SIGNATURE), sizeof(UCHAR));
                RtlCopyMemory(user_hmac_signature.hmac, ((USER_HMAC_SIGNATURE*)input_buffer)->hmac, HMAC_SIZE);
            } except(exception_handler(GetExceptionInformation(), TRUE)) {
                return GetExceptionCode();
            }

            NTSTATUS status = verify_HMAC_SHA256_signature(g_context.nonce, user_hmac_signature.hmac);
            if (NT_SUCCESS(status)) {
                g_context.connection_state = CONNECTION_AUTHENTICATED;
                DbgPrint("Connection authenticated.\n");
                return STATUS_SUCCESS;
            }
            else {
                DbgPrint("Authentication failed, closing client port.\n");
                if (g_context.client_port != NULL) {
                    FltCloseClientPort(g_context.registered_filter, &g_context.client_port);
                    g_context.client_port = NULL;
                }
                return STATUS_ACCESS_DENIED;
            }

        }
        break;

        case CONNECTION_AUTHENTICATED:
        {
            USER_INITIAL_CONTEXT user_initial_context = { 0 };

            try {
                if (input_buffer_length < sizeof(USER_INITIAL_CONTEXT)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                ProbeForRead(input_buffer, sizeof(USER_INITIAL_CONTEXT), __alignof(USER_INITIAL_CONTEXT));
                RtlCopyMemory(&user_initial_context, input_buffer, sizeof(USER_INITIAL_CONTEXT));
            }
            except (exception_handler(GetExceptionInformation(), TRUE)) {
                return GetExceptionCode();
            }

            g_context.agent_process_id = user_initial_context.process_id;
            RtlCopyMemory(g_context.agent_installation_path, user_initial_context.installation_path, sizeof(user_initial_context.installation_path));
            RtlCopyMemory(g_context.local_db_path, user_initial_context.local_db_path, sizeof(user_initial_context.local_db_path));

            if (user_initial_context.policy_count == 0 ||
                user_initial_context.policy_count > MAX_POLICY_COUNT) {
                return STATUS_INVALID_PARAMETER;
            }

            // Initialize ART, add policies sent by user
            art_init_tree(&g_art_tree);

            SIZE_T sizeof_policy_array = user_initial_context.policy_count * sizeof(POLICY);
            try {
                ProbeForRead(user_initial_context.policies, sizeof_policy_array, __alignof(POLICY));
            }
            except(exception_handler(GetExceptionInformation(), TRUE)) {
                return GetExceptionCode();
            }

            for (UINT16 i = 0; i < user_initial_context.policy_count; ++i) {
                POLICY policy;
                UNICODE_STRING unicode_string;
                RtlCopyMemory(&policy, &user_initial_context.policies[i], sizeof(POLICY));
                policy.path[MAX_FILE_NAME_LENGTH - 1] = L'\0';
                RtlInitUnicodeStringEx(&unicode_string, policy.path);
                art_insert(&g_art_tree, &unicode_string, &policy.access_mask);
            }

#if TEST
            print(g_art_tree.root, 0);
#endif
            //DbgPrint("Connection established.\n");
            //if ((input_buffer == NULL) ||
            //    (input_buffer_length < (FIELD_OFFSET(USER_RESPONSE, operation_id) +
            //        sizeof(USER_RESPONSE)))) {
            //    return STATUS_INVALID_PARAMETER;
            //}

            //USER_RESPONSE reply;
            //try {
            //    reply.operation_id = ((USER_RESPONSE*)input_buffer)->operation_id;
            //    reply.allow = ((USER_RESPONSE*)input_buffer)->allow;
            //} except(exception_handler(GetExceptionInformation(), TRUE)) {

            //    return GetExceptionCode();
            //}

            //PENDING_OPERATION* replied_operation = pending_operation_list_remove_by_id(reply.operation_id);
            //if (replied_operation == NULL) {
            //    // TODO replied operation doesnt exist in the pending list
            //    return STATUS_UNSUCCESSFUL;
            //}

            //if (reply.allow == TRUE) {
            //    replied_operation->data->IoStatus.Status = STATUS_SUCCESS;
            //    FltCompletePendedPreOperation(replied_operation->data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
            //}
            //else {
            //    replied_operation->data->IoStatus.Status = STATUS_ACCESS_DENIED;
            //    replied_operation->data->IoStatus.Information = 0;
            //    FltCompletePendedPreOperation(replied_operation->data, FLT_PREOP_COMPLETE, NULL);

            //}

            //ExFreePoolWithTag(replied_operation, PENDING_OPERATION_TAG);

            return STATUS_SUCCESS;
        }
        break;

        default: 
            return STATUS_ACCESS_DENIED;
    }
}



NTSTATUS create_minifilter_request(_In_ PFLT_CALLBACK_DATA data, _In_ ULONG operation_id, _In_ OPERATION_TYPE operation_type, _Out_ MINIFILTER_REQUEST* message, PCFLT_RELATED_OBJECTS filter_objects) {

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
        message->target_name[259] = '\0';
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
    message->file_name[259] = '\0';

    return STATUS_SUCCESS;
}

NTSTATUS send_message_to_user(_In_ MINIFILTER_REQUEST* message)
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
        sizeof(MINIFILTER_REQUEST),
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

    switch (data->Iopb->MajorFunction) {

        case IRP_MJ_CREATE:
        {
            ULONG createOptions = data->Iopb->Parameters.Create.Options;

            if ((createOptions & FILE_DELETE_ON_CLOSE) == FILE_DELETE_ON_CLOSE) {
                operation_type = OPERATION_TYPE_FILE_ON_CLOSE;
            }

        }
        break;

        case IRP_MJ_SET_INFORMATION:
        {
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
        break;

        //case IRP_MJ_READ:
        //    operation_type = OPERATION_TYPE_READ;
        //    break;

        //case IRP_MJ_WRITE:
        //    operation_type = OPERATION_TYPE_WRITE;
        //    break;

        default:
            operation_type = OPERATION_TYPE_INVALID;
            break;
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
