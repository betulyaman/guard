#include "policy_manager.h"

#include "adaptive_radix_tree.h"
#include "global_context.h"

NTSTATUS policy_initialize() {
    if (!g_context.policies) {
        return STATUS_INVALID_PARAMETER;
    }

    g_art_root = art_create_node(NODE4);
    if (!g_art_root) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < POLICY_NUMBER; i++) {
        UNICODE_STRING path;
        RtlInitUnicodeString(&path, g_context.policies[i].path);
        if (!art_insert(&g_art_root, &path, g_context.policies[i].access_mask)) {
            return STATUS_UNSUCCESSFUL;
        }
    }
    return STATUS_SUCCESS;
}
