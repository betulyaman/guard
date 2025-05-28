#ifndef GUARD_PENDING_OPERATION_LIST_H
#define GUARD_PENDING_OPERATION_LIST_H

#include <fltKernel.h>

#define PENDING_OPERATION_TAG 'popt'

typedef struct {
	LIST_ENTRY list_entry;
	ULONG operation_id;
	LARGE_INTEGER time;
	PFLT_CALLBACK_DATA data;
} PENDING_OPERATION;

extern FAST_MUTEX g_pending_operation_list_lock;
extern LIST_ENTRY g_pending_operation_list;
extern ULONG g_operation_id;

VOID pending_operation_list_initialize();
VOID pending_operation_list_append(_In_ PENDING_OPERATION* operation);
PENDING_OPERATION* pending_operation_list_remove_by_id(_In_ CONST ULONG operation_id);
VOID pending_operation_list_clear();
VOID pending_operation_list_timeout_clear();

NTSTATUS add_operation_to_pending_list(_In_ PFLT_CALLBACK_DATA data, _In_ ULONG operation_id);

#endif // GUARD_PENDING_OPERATION_LIST_H
