#include "windows_service_controls.h"

BOOLEAN is_suffix(PUNICODE_STRING str, PCWSTR suffix)
{
    UNICODE_STRING suffix_str;
    RtlInitUnicodeString(&suffix_str, suffix);

    if (str->Length < suffix_str.Length) {
        return FALSE;
    }

    USHORT offset = (str->Length - suffix_str.Length) / sizeof(WCHAR);
    UNICODE_STRING substr = { .Buffer = str->Buffer + offset, .Length = suffix_str.Length, .MaximumLength = suffix_str.Length };
    if (RtlCompareUnicodeString(&suffix_str, &substr, TRUE) == 0) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

BOOLEAN is_trusted_executable(PUNICODE_STRING image_path)
{
    for (int i = 0; i < ARRAYSIZE(g_trusted_executables); ++i) {
        if (is_suffix(image_path, g_trusted_executables[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN is_process_token_trusted(PEPROCESS process)
{
    PACCESS_TOKEN token = PsReferencePrimaryToken(process);
    if (!token) {
        return FALSE;
    }

    PTOKEN_USER token_user = NULL;
    if (!NT_SUCCESS(SeQueryInformationToken(token, TokenUser, (PVOID*)&token_user)) && token_user) {
        ObDereferenceObject(token);
        return FALSE;
    }

    UNICODE_STRING sid_str;
    WCHAR sid_buffer[128];
    sid_str.Buffer = sid_buffer;
    sid_str.MaximumLength = sizeof(sid_buffer);
    sid_str.Length = 0;

    if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&sid_str, token_user->User.Sid, TRUE))) {
        ExFreePool(token_user);
        ObDereferenceObject(token);
        return FALSE;
    }


    for (int i = 0; i < ARRAYSIZE(g_trusted_sids); ++i) {
        UNICODE_STRING trusted_sid;
        RtlInitUnicodeString(&trusted_sid, g_trusted_sids[i]);
        if (RtlEqualUnicodeString(&sid_str, &trusted_sid, TRUE)) {
            ExFreePool(token_user);
            ObDereferenceObject(token);
            return TRUE;
        }
    }

    ExFreePool(token_user);
    ObDereferenceObject(token);
    return FALSE;
}

BOOLEAN is_trusted_installer_process()
{
    PEPROCESS process = PsGetCurrentProcess();

    PUNICODE_STRING image_path = NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(process, &image_path)) || !image_path) {
        ExFreePool(image_path);
        return FALSE;
    }

    if (!is_trusted_executable(image_path)) {
        ExFreePool(image_path);
        return FALSE;
    }

    if (!is_process_token_trusted(process)) {
        ExFreePool(image_path);
        return FALSE;
    }

    ExFreePool(image_path);
    return TRUE;
}
