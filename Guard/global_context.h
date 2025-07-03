#ifndef GUARD_GLOBAL_CONTEXT_H
#define GUARD_GLOBAL_CONTEXT_H

#include "communication.h"

#include <fltKernel.h>

#define MEMORY_TAG 'GFMT'

typedef struct {
	LONG agent_process_id;
	WCHAR agent_installation_path[MAX_FILE_NAME_LENGTH];
	WCHAR local_db_path[MAX_FILE_NAME_LENGTH];
	PFLT_FILTER registered_filter;
	PFLT_PORT server_port;
	PFLT_PORT client_port;
	POLICY policies[POLICY_NUMBER];
} GLOBAL_CONTEXT;

extern GLOBAL_CONTEXT g_context;

VOID initalize_global_context();

#endif //GUARD_GLOBAL_CONTEXT_H