#ifndef GUARD_WINDOWS_SERVICEs_CONTROL_H
#define GUARD_WINDOWS_SERVICEs_CONTROL_H

#include <ntifs.h>

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

typedef struct {
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct {
    PS_PROTECTION Protection;
} PROCESS_PROTECTION_INFORMATION;


static const WCHAR* g_trusted_executables[] = {
    L"\\System32\\TrustedInstaller.exe",
    L"\\System32\\wuauclt.exe",
    L"\\System32\\msiexec.exe",
    L"\\System32\\usoclient.exe",
    L"\\System32\\MoUsoCoreWorker.exe",
    L"\\System32\\compattelrunner.exe"
};

static const WCHAR* g_trusted_sids[] = {
    L"S-1-5-18", // SYSTEM
    L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
};

BOOLEAN is_trusted_installer_process();
BOOLEAN is_process_token_trusted(PEPROCESS process);
BOOLEAN is_trusted_executable(PUNICODE_STRING imagePath);
BOOLEAN is_suffix(PUNICODE_STRING str, PCWSTR suffix);

#endif //GUARD_WINDOWS_SERVICEs_CONTROL_H

