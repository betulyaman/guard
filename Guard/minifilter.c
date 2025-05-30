#include "global_context.h"

#include "communication.h"
#include "log.h"
#include "preoperation_callbacks.h"
#include "pending_operation_list.h"

#include <fltKernel.h>

NTSTATUS register_filter(_In_ PDRIVER_OBJECT driver_object);
NTSTATUS filter_unload_callback(FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS filter_tear_down_callback(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT driver_object,
	_In_ PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(registry_path);

	NTSTATUS status = STATUS_SUCCESS;

	try {

		pending_operation_list_initialize();

		status = register_filter(driver_object);
		if (!NT_SUCCESS(status)) {
			LOG_MSG("register_filter failed. status 0x%x", status);
			return status;
		}

		status = create_communication_port();
		if (!NT_SUCCESS(status)) {
			LOG_MSG("create_communication_port failed, status: 0x%x", status);
			leave;
		}

		status = FltStartFiltering(g_context.registered_filter);
		if (!NT_SUCCESS(status)) {
			LOG_MSG("FltStartFiltering failed, status: 0x%x", status);
			leave;
		}
	}
	finally {

		if (!NT_SUCCESS(status)) {

			if (NULL != g_context.server_port) {
				FltCloseCommunicationPort(g_context.server_port);
			}

			if (NULL != g_context.registered_filter) {
				FltUnregisterFilter(g_context.registered_filter);
			}
		}
	}
	return status;
}

NTSTATUS filter_unload_callback(FLT_FILTER_UNLOAD_FLAGS flags)
{
	UNREFERENCED_PARAMETER(flags);

	if (g_context.server_port != NULL) {
		FltCloseCommunicationPort(g_context.server_port);
		g_context.server_port = NULL;
	}

	if (g_context.client_port != NULL) {
		FltCloseClientPort(g_context.registered_filter, &g_context.client_port);
		g_context.client_port = NULL;
	}

	if (g_context.registered_filter != NULL) {
		FltUnregisterFilter(g_context.registered_filter);
		g_context.registered_filter = NULL;
	}

	pending_operation_list_clear();
	return STATUS_SUCCESS;
}

NTSTATUS filter_tear_down_callback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	return STATUS_SUCCESS;
}

NTSTATUS register_filter(_In_ PDRIVER_OBJECT driver_object)
{
	CONST FLT_OPERATION_REGISTRATION callbacks[] = {
	{ IRP_MJ_CREATE, 0, pre_operation_callback, NULL },
	{ IRP_MJ_CLEANUP,0, pre_operation_callback, NULL },
	{ IRP_MJ_CLOSE,  0, pre_operation_callback, NULL },
	{ IRP_MJ_DIRECTORY_CONTROL, 0, pre_operation_callback, NULL },
	{ IRP_MJ_SET_INFORMATION,   0, pre_operation_callback, NULL },
	{ IRP_MJ_SET_SECURITY,      0, pre_operation_callback, NULL },
	{ IRP_MJ_READ,              0, pre_operation_callback, NULL },
	{ IRP_MJ_QUERY_INFORMATION, 0, pre_operation_callback, NULL },
	{ IRP_MJ_QUERY_SECURITY,    0, pre_operation_callback, NULL },
	{ IRP_MJ_WRITE,             0, pre_operation_callback, NULL },
	{ IRP_MJ_OPERATION_END }
	};

	CONST FLT_REGISTRATION registration_data = {
		.Size = sizeof(FLT_REGISTRATION),
		.Version = FLT_REGISTRATION_VERSION,
		.Flags = 0,
		.ContextRegistration = NULL,
		.OperationRegistration = callbacks,
		.FilterUnloadCallback = filter_unload_callback,
		.InstanceSetupCallback = NULL,
		.InstanceQueryTeardownCallback = filter_tear_down_callback,
		.InstanceTeardownStartCallback = NULL,
		.InstanceTeardownCompleteCallback = NULL,
		.GenerateFileNameCallback = NULL,
		.NormalizeNameComponentCallback = NULL,
		.NormalizeContextCleanupCallback = NULL,
		.TransactionNotificationCallback = NULL,
		.NormalizeNameComponentExCallback = NULL,
		.SectionNotificationCallback = NULL,
	};

	return FltRegisterFilter(driver_object, &registration_data, &g_context.registered_filter);
}
