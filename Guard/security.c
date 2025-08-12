#include "security.h"

#include "communication.h"
#include "log.h"

#include <bcrypt.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#define HASH_OBJECT_TAG 'cesT'

// the secret key for HMAC
// openssl rand -hex 32
const UCHAR SHARED_SECRET_KEY[] = {
    0xB3, 0x6F, 0xE2, 0x45, 0x1D, 0x89, 0x0A, 0x7E,
    0x4C, 0x91, 0x3B, 0xDF, 0xFA, 0x6B, 0xC2, 0x3A,
    0x5D, 0x8F, 0xE4, 0x2B, 0x3D, 0xC9, 0x0E, 0x87,
    0x71, 0xA3, 0x5C, 0xF1, 0x48, 0x92, 0x0D, 0x6E
};

NTSTATUS verify_HMAC_SHA256_signature(
    _In_reads_bytes_(NONCE_SIZE) PUCHAR nonce,
    _In_reads_bytes_(HMAC_SIZE) PUCHAR received_signature)
{
    // Opens the SHA256 hashing algorithm for HMAC use.
    // Returns a handle to use for hashing.
    BCRYPT_ALG_HANDLE hmac_sha256_handle = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hmac_sha256_handle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptOpenAlgorithmProvider failed: 0x%08X\n", status);
        return status;
    }

    // Determines the required size for the hash object buffer for this algorithm.
    ULONG hash_object_size = 0;
    ULONG result = 0;
    status = BCryptGetProperty(
        hmac_sha256_handle,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&hash_object_size,
        sizeof(ULONG),
        &result,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptGetProperty failed: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hmac_sha256_handle, 0);
        return status;
    }

    PUCHAR hash_object = ExAllocatePoolWithTag(NonPagedPoolNx, hash_object_size, HASH_OBJECT_TAG);
    if (!hash_object) {
        BCryptCloseAlgorithmProvider(hmac_sha256_handle, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlSecureZeroMemory(hash_object, hash_object_size);

    // Creates an HMAC hash object.
    // Binds the shared secret key to the hash object.
    // Returns hash handle, used for hashing data(nonce) securely.
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    status = BCryptCreateHash(
        hmac_sha256_handle,
        &hash_handle,
        hash_object,
        hash_object_size,
        (PUCHAR)SHARED_SECRET_KEY,
        SHARED_SECRET_KEY_SIZE,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptCreateHash failed: 0x%08X\n", status);
        ExFreePool2(hash_object, HASH_OBJECT_TAG, NULL, 0);
        BCryptCloseAlgorithmProvider(hmac_sha256_handle, 0);
        return status;
    }

    // Performs a one way hash or Message Authentication Code (MAC) on a data buffer
    status = BCryptHashData(
        hash_handle,
        (PUCHAR)nonce,
        NONCE_SIZE,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptHashData failed: 0x%08X\n", status);
        BCryptDestroyHash(hash_handle);
        ExFreePool2(hash_object, HASH_OBJECT_TAG, NULL, 0);
        BCryptCloseAlgorithmProvider(hmac_sha256_handle, 0);
        return status;
    }

    // Finalizes the HMAC computation.
    // Places the computed HMAC - SHA256 result(32 bytes) into CalcSignature.
    UCHAR computed_signature[HMAC_SIZE];
    status = BCryptFinishHash(
        hash_handle,
        computed_signature,
        HMAC_SIZE,
        0
    );
    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptFinishash_handle failed: 0x%08X\n", status);
        BCryptDestroyHash(hash_handle);
        ExFreePool2(hash_object, HASH_OBJECT_TAG, NULL, 0);
        BCryptCloseAlgorithmProvider(hmac_sha256_handle, 0);
        return status;
    }

    // constant - time comparison (instead of RtlCompareMemory) to mitigate timing attacks.
    BOOLEAN equal = TRUE;
    for (ULONG i = 0; i < HMAC_SIZE; ++i) {
        if(computed_signature[i] != received_signature[i]) {
            equal = FALSE;
        }
        //equal &= (computed_signature[i] == received_signature[i]);
    }
    if (!equal) {
        status = STATUS_ACCESS_DENIED;
        LOG_MSG("HMAC Signature verification failed.\n");
    }
    else {
        status = STATUS_SUCCESS;
        LOG_MSG("HMAC Signature verification succeeded.\n");
    }

    return status;
}

NTSTATUS generate_secure_nonce(
    _Out_writes_bytes_(nonce_size) PUCHAR nonce,
    _In_ ULONG nonce_size) 
{
    if (nonce == NULL || nonce_size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = BCryptGenRandom(
        NULL,
        nonce,
        nonce_size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!NT_SUCCESS(status)) {
        LOG_MSG("BCryptGenRandom failed with status 0x%x", status);
    }

    return status;
}