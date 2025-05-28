#include "preoperation_callbacks.h"

#include "global_context.h"
#include "communication.h"
#include "pending_operation_list.h"
#include "restrictions.h"
#include "windows_service_controls.h"

#include <fltKernel.h>
#include <ntstrsafe.h>

ULONG g_operation_id;

BOOLEAN is_agent_connected();

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
	UNREFERENCED_PARAMETER(completion_callback);

	// Check if Agent connected for debugging !!
	if (!is_agent_connected()) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Check if the requester is Agent
	// Do not block Agent
	if (FltGetRequestorProcessId(data) == (ULONG)g_context.agent_process_id) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Do not block the windows services
	if (is_trusted_installer_process()) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Block accessing the restricted path
	if (is_in_restricted_path(data)) {
		data->IoStatus.Status = STATUS_ACCESS_DENIED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

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

BOOLEAN is_agent_connected() {
	return (g_context.client_port != NULL);
}