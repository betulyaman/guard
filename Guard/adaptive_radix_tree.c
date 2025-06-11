#include "adaptive_radix_tree.h"

#include "global_context.h"

#include <ntifs.h>
#include <ntddk.h>

ART_NODE* g_art_root;

ART_NODE* art_create_node(NODE_TYPE type) {
    ART_NODE* node = (ART_NODE*)ExAllocatePoolWithTag(PagedPool, sizeof(ART_NODE), 'ARTT');
    if (node) {
        RtlZeroMemory(node, sizeof(ART_NODE));
        node->type = type;
        node->num_of_child = 0;
        node->is_end = FALSE;
        node->access_rights = 0;
    }
    return node;
}

BOOLEAN art_insert_child(ART_NODE* node, UCHAR key_byte, ART_NODE* child, UINT32 access_mask) {
    if (node->type == NODE4) {
        if (node->num_of_child < 4) {
            node->node_type.node4.keys[node->num_of_child] = key_byte;
            node->node_type.node4.children[node->num_of_child] = child;
            node->num_of_child++;
            node->access_rights = access_mask;
        }
        else {
            // Upgrade to node_type.node16
            ART_NODE* new_node = art_create_node(NODE16);
            if (!new_node) {
                return FALSE;
            }

            RtlCopyMemory(new_node->node_type.node16.keys, node->node_type.node4.keys, 4);
            RtlCopyMemory(new_node->node_type.node16.children, node->node_type.node4.children, 4 * sizeof(ART_NODE*));
            new_node->num_of_child = 4;

            new_node->node_type.node16.keys[4] = key_byte;
            new_node->node_type.node16.children[4] = child;
            new_node->num_of_child++;
            new_node->access_rights = access_mask;
            RtlCopyMemory(node, new_node, sizeof(ART_NODE));
            ExFreePoolWithTag(new_node, 'TrAd');
        }
    }
    else if (node->type == NODE16) {
        if (node->num_of_child < 16) {
            node->node_type.node16.keys[node->num_of_child] = key_byte;
            node->node_type.node16.children[node->num_of_child] = child;
            node->num_of_child++;
            node->access_rights = access_mask;
        }
        else {
            // Upgrade to node_type.node48
            ART_NODE* new_node = art_create_node(NODE48);
            if (!new_node) {
                return FALSE;
            }

            RtlZeroMemory(new_node->node_type.node48.child_index, 256);
            for (USHORT i = 0; i < 16; i++) {
                new_node->node_type.node48.child_index[node->node_type.node16.keys[i]] = (UCHAR)(i + 1);
                new_node->node_type.node48.children[i] = node->node_type.node16.children[i];
            }
            new_node->node_type.node48.child_index[key_byte] = 17;
            new_node->node_type.node48.children[16] = child;
            new_node->num_of_child = 17;
            new_node->access_rights = access_mask;

            RtlCopyMemory(node, new_node, sizeof(ART_NODE));
            ExFreePoolWithTag(new_node, 'TrAd');
        }
    }
    else if (node->type == NODE48) {
        if (node->num_of_child < 48) {
            USHORT pos = node->num_of_child;
            node->node_type.node48.child_index[key_byte] = (UCHAR)(pos + 1);
            node->node_type.node48.children[pos] = child;
            node->num_of_child++;
            node->access_rights = access_mask;
        }
        else {
            // Upgrade to node_type.node256
            ART_NODE* new_node = art_create_node(NODE256);
            if (!new_node) {
                return FALSE;
            }

            for (USHORT i = 0; i < 256; i++) {
                if (node->node_type.node48.child_index[i]) {
                    USHORT index = node->node_type.node48.child_index[i] - 1;
                    new_node->node_type.node256.children[i] = node->node_type.node48.children[index];
                }
            }
            new_node->node_type.node256.children[key_byte] = child;
            new_node->num_of_child = node->num_of_child + 1;
            new_node->access_rights = access_mask;

            RtlCopyMemory(node, new_node, sizeof(ART_NODE));
            ExFreePoolWithTag(new_node, 'TrAd');
        }
    }
    else if (node->type == NODE256) {
        if (!node->node_type.node256.children[key_byte]) {
            node->num_of_child++;
        }
        node->node_type.node256.children[key_byte] = child;
        node->access_rights = access_mask;
    }

    return TRUE;
}

ART_NODE* art_find_child(ART_NODE* node, UCHAR key_byte) {
    if (!node) {
        return NULL;
    }

    if (node->type == NODE4) {
        for (USHORT i = 0; i < node->num_of_child; i++) {
            if (node->node_type.node4.keys[i] == key_byte) {
                return node->node_type.node4.children[i];
            }
        }
    }
    else if (node->type == NODE16) {
        for (USHORT i = 0; i < node->num_of_child; i++) {
            if (node->node_type.node16.keys[i] == key_byte) {
                    return node->node_type.node16.children[i];
            }
        }
    }
    else if (node->type == NODE48) {
        UCHAR index = node->node_type.node48.child_index[key_byte];
        if (index) {
            return node->node_type.node48.children[index - 1];
        }
    }
    else if (node->type == NODE256) {
        return node->node_type.node256.children[key_byte];
    }
    return NULL;
}

BOOLEAN art_insert(ART_NODE* root, PCUNICODE_STRING key, UINT32 access_mask) {
    if (!root) {
        return FALSE;
    }

    BOOLEAN is_inserted = FALSE;
    ART_NODE* current_node = root;
    for (USHORT i = 0; i < key->Length / sizeof(WCHAR); i++) {
        UCHAR key_byte = (UCHAR)key->Buffer[i];
        ART_NODE* child = art_find_child(current_node, key_byte);
        if (!child) {
            child = art_create_node(NODE4);
            if (child) {
                is_inserted = art_insert_child(current_node, key_byte, child, access_mask);
            }
        }
        current_node = child;
        is_inserted = TRUE;
    }
    current_node->is_end = TRUE;

    return is_inserted;
}

BOOLEAN art_search(ART_NODE* root, PCUNICODE_STRING key) {
    ART_NODE* current_node = root;
    for (USHORT i = 0; i < key->Length / sizeof(WCHAR); i++) {
        UCHAR key_byte = (UCHAR)key->Buffer[i];
        current_node = art_find_child(current_node, key_byte);
        if (!current_node) {
            return FALSE;
        }
    }
    return current_node->is_end;
}

VOID art_free_node(ART_NODE* node) {
    if (node) {
        if (node->type == NODE4) {
            for (USHORT i = 0; i < node->num_of_child; i++) {
                art_free_node(node->node_type.node4.children[i]);
            }
        }
        else if (node->type == NODE16) {
            for (USHORT i = 0; i < node->num_of_child; i++) {
                art_free_node(node->node_type.node16.children[i]);
            }
        }
        else if (node->type == NODE48) {
            for (USHORT i = 0; i < 256; i++) {
                UCHAR index = node->node_type.node48.child_index[i];
                if (index) {
                    art_free_node(node->node_type.node48.children[index - 1]);
                }
            }
        }
        else if (node->type == NODE256) {
            for (USHORT i = 0; i < 256; i++) {
                art_free_node(node->node_type.node256.children[i]);
            }
        }

        ExFreePoolWithTag(node, 'TrAd');
    }
}

NTSTATUS policy_initialize() {
    if (!g_context.policies) {
        return STATUS_INVALID_PARAMETER;
    }

    g_art_root = art_create_node(NODE4);
    if (!g_art_root) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNICODE_STRING path;
    for (int i = 0; i < POLICY_NUMBER; ++i) {
        RtlInitUnicodeString(&path, g_context.policies[i].path);
        BOOLEAN is_inserted = art_insert(g_art_root, &path, g_context.policies[i].access_mask);
        if (!is_inserted) {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}
