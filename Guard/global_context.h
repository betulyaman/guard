#ifndef GUARD_GLOBAL_CONTEXT_H
#define GUARD_GLOBAL_CONTEXT_H

#include <fltKernel.h>

#define MEMORY_TAG 'GFMT'

typedef struct {
	LONG agent_process_id;
	WCHAR agent_path[256];
	PFLT_FILTER registered_filter;
	PFLT_PORT server_port;
	PFLT_PORT client_port;
} MINIFILTER_CONTEXT;

extern MINIFILTER_CONTEXT g_context;

#endif //GUARD_GLOBAL_CONTEXT_H