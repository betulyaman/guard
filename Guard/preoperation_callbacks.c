#include "preoperation_callbacks.h"

#include <fltKernel.h>
#include <ntstrsafe.h>

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
		data->IoStatus.Status = STATUS_ACCESS_DENIED;
		data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
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
			data->IoStatus.Status = STATUS_ACCESS_DENIED;
			data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
