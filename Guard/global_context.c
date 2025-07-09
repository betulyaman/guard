#include "global_context.h"

#include <ntstrsafe.h>

GLOBAL_CONTEXT g_context;

VOID initalize_global_context() {
    g_context.connection_state = CONNECTION_CLOSED;

    // When the minifilter connects to Agent, agent_installation_path and
    // local_db_path values are updated with the paths sent by Agent.
    WCHAR default_installation_path[MAX_FILE_NAME_LENGTH] = L"\\Device\\HarddiskVolume3\\Program Files\\iCredible\\File-Security";
    NTSTATUS status = RtlStringCchCopyW(g_context.agent_installation_path, MAX_FILE_NAME_LENGTH, default_installation_path);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(g_context.agent_installation_path, MAX_FILE_NAME_LENGTH);
    }

    WCHAR default_local_db_path[MAX_FILE_NAME_LENGTH] = L"\\Device\\HarddiskVolume3\\FileSecDb";
    status = RtlStringCchCopyW(g_context.local_db_path, MAX_FILE_NAME_LENGTH, default_local_db_path);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(g_context.local_db_path, MAX_FILE_NAME_LENGTH);
    }
}