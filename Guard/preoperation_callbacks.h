#ifndef GUARD_PREOPERATION_CALLBACKS_H
#define GUARD_PREOPERATION_CALLBACKS_H

#include <fltKernel.h>

FLT_PREOP_CALLBACK_STATUS pre_create_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_callback
);

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS filter_objects,
	_Flt_CompletionContext_Outptr_ PVOID* completion_context
);

#endif // GUARD_PREOPERATION_CALLBACKS_H