#ifndef FILE_INTEGRITY_MONITORING_COMMUNICATION_H
#define FILE_INTEGRITY_MONITORING_COMMUNICATION_H

#include <fltKernel.h>

#define COMMUNICATION_PORT_NAME L"\\MinifilterCommunicationPort"

NTSTATUS connect_notify_callback(
	_In_ PFLT_PORT client_port,
	_In_ PVOID server_port_cookie,
	_In_reads_bytes_(size_of_context) PVOID conneciton_context,
	_In_ ULONG size_of_context,
	_Outptr_result_maybenull_ PVOID* connection_cookie);

VOID disconnect_notify_callback(_In_opt_ PVOID connection_cookie);

NTSTATUS create_communication_port();

#endif //FILE_INTEGRITY_MONITORING_COMMUNICATION_H