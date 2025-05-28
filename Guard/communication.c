#include "communication.h"

#include "global_context.h"
#include "log.h"

#include <ntstrsafe.h>

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
		NULL,
		1);

	FltFreeSecurityDescriptor(security_descriptor);

	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(g_context.registered_filter);
	}

	return status;
}
