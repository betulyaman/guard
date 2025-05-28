#include "preoperation_callbacks.h"

#include "pending_operation_list.h"
#include "communication.h"

#include <fltKernel.h>
#include <ntstrsafe.h>

ULONG g_operation_id;

FLT_PREOP_CALLBACK_STATUS pre_create_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
	UNREFERENCED_PARAMETER(filter_objects);
	UNREFERENCED_PARAMETER(completion_callback);

	// Block DELETE operation
	ULONG file_operation_options = data->Iopb->Parameters.Create.Options;
	if ((file_operation_options & FILE_DELETE_ON_CLOSE) == FILE_DELETE_ON_CLOSE) {
		NTSTATUS status = add_operation_to_pending_list(data, g_operation_id);
		if (!NT_SUCCESS(status)) {
			data->IoStatus.Status = STATUS_UNSUCCESSFUL;
			return FLT_PREOP_COMPLETE;
		}

		g_operation_id++;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
	UNREFERENCED_PARAMETER(filter_objects);
	UNREFERENCED_PARAMETER(completion_callback);

	OPERATION_TYPE operation_type = get_operation_type(data, filter_objects);
	if (operation_type == OPERATION_TYPE_INVALID) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	CONFIRMATION_MESSAGE message;
	NTSTATUS status = create_confirmation_message(data, g_operation_id, operation_type, &message, filter_objects);
	if (!NT_SUCCESS(status)) {
		data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		return FLT_PREOP_COMPLETE;
	}

	status = send_message_to_user(&message);
	if (!NT_SUCCESS(status)) {
		data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		return FLT_PREOP_COMPLETE;
	}

	status = add_operation_to_pending_list(data, g_operation_id);
	if (!NT_SUCCESS(status)) {
		data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		return FLT_PREOP_COMPLETE;
	}

	g_operation_id++;
	
	pending_operation_list_timeout_clear();

	return FLT_PREOP_PENDING;
}
