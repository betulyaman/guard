#ifndef GUARD_SECURITY_H
#define GUARD_SECURITY_H

#include "communication.h"

#include <fltKernel.h>

#define NONCE_SIZE 32
#define HMAC_SIZE 32
#define SHARED_SECRET_KEY_SIZE 32

extern const UCHAR SHARED_SECRET_KEY[SHARED_SECRET_KEY_SIZE];

typedef struct {
	UCHAR hmac[HMAC_SIZE];
} USER_HMAC_SIGNATURE;

NTSTATUS verify_HMAC_SHA256_signature(
	_In_reads_bytes_(NONCE_SIZE) PUCHAR nonce,
	_In_reads_bytes_(HMAC_SIZE) PUCHAR received_signature);

NTSTATUS generate_secure_nonce(
	_Out_writes_bytes_(nonce_size) PUCHAR nonce, 
	_In_ ULONG nonce_size);

#endif //GUARD_SECURITY_H
