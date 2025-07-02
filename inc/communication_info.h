#ifndef GUARD_COMMUNICATION_INFO_H
#define GUARD_COMMUNICATION_INFO_H

#include <ntifs.h>

#define COMMUNICATION_PORT_NAME L"\\CommunicationPort"
#define MAX_FILE_NAME_LENGTH 260
#define POLICY_NUMBER 3

typedef enum {
	OPERATION_TYPE_INVALID = 0,
//	OPERATION_TYPE_CREATE,
	OPERATION_TYPE_DELETE,
	OPERATION_TYPE_FILE_ON_CLOSE,
	OPERATION_TYPE_MOVE,
//	OPERATION_TYPE_READ,
	OPERATION_TYPE_RENAME,
//	OPERATION_TYPE_WRITE,
} OPERATION_TYPE;

typedef struct {
	ULONG operation_id;
	BOOLEAN allow;
} USER_RESPONSE;

typedef struct {
	ULONG operation_id;
	UINT16 operation_type;
	WCHAR target_name[260];
	WCHAR file_name[260];
} MINIFILTER_REQUEST;

typedef struct {
	ULONG access_mask;
	WCHAR path[260];
} POLICY;

typedef struct {
	ULONG token;
	LONG process_id;
	WCHAR restricted_path[260];
	//POLICY policies[POLICY_NUMBER];
} HANDSHAKE_INFO;

#endif //GUARD_COMMUNICATION_INFO_H