#include "preoperation_callbacks.h"

#include <fltKernel.h>
#include <ntstrsafe.h>

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
) {
	UNREFERENCED_PARAMETER(data);
	UNREFERENCED_PARAMETER(filter_objects);
	UNREFERENCED_PARAMETER(completion_callback);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
