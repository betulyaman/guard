#include "preoperation_callbacks.h"

#include "pending_operation_list.h"

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

	if (data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
		FILE_INFORMATION_CLASS file_information_class = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
		if (file_information_class == FileDispositionInformation ||
			file_information_class == FileDispositionInformationEx) {

			NTSTATUS status = add_operation_to_pending_list(data, g_operation_id);
			if (!NT_SUCCESS(status)) {
				data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				return FLT_PREOP_COMPLETE;
			}

			g_operation_id++;

		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
