#include "adaptive_radix_tree.h"

#include <ntifs.h>

#define ART_TAG 'trAd'

ART_NODE* g_art_root = NULL;

static BOOLEAN unicode_to_utf8(PCUNICODE_STRING unicode, PUCHAR buffer, SIZE_T buffer_size, PSIZE_T out_length) {
    if (!unicode || !buffer || !out_length) {
        return FALSE;
    }

    NTSTATUS status = RtlUnicodeToUTF8N((PCHAR)buffer, (ULONG)buffer_size, (PULONG)out_length, unicode->Buffer, unicode->Length);
    return NT_SUCCESS(status);
}

ART_NODE* art_create_node(NODE_TYPE type) {
    SIZE_T size;
    switch (type) {
        case NODE4:   
            size = sizeof(ART_NODE4); 
            break;
        case NODE16:  
            size = sizeof(ART_NODE16); 
            break;
        case NODE48:  
            size = sizeof(ART_NODE48); 
            break;
        case NODE256: 
            size = sizeof(ART_NODE256); 
            break;
        default: 
            return NULL;
    }

    ART_NODE* node = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, ART_TAG);
    if (!node) {
        return NULL;
    }

    RtlZeroMemory(node, size);
    node->type = type;
    return node;
}

static VOID art_upgrade_node(ART_NODE** node_ref, NODE_TYPE new_type) {
    if (!node_ref || !(*node_ref)) {
        return;
    }

    ART_NODE* old = *node_ref;
    ART_NODE* new = art_create_node(new_type);
    if (!new) {
        return;
    }

    new->is_end = old->is_end;
    new->access_rights = old->access_rights;
    new->prefix_length = old->prefix_length;
    RtlCopyMemory(new->prefix, old->prefix, MAX_PREFIX_LENGTH);

    USHORT i;
    switch (old->type) {
    case NODE4: {
        ART_NODE4* old4 = (ART_NODE4*)old;
        if (new_type == NODE16) {
            ART_NODE16* new16 = (ART_NODE16*)new;
            for (i = 0; i < old->num_of_child; i++) {
                    new16->keys[i] = old4->keys[i];
                new16->children[i] = old4->children[i];
            }
        }
        break;
    }
    case NODE16: {
        ART_NODE16* old16 = (ART_NODE16*)old;
        if (new_type == NODE48) {
            ART_NODE48* new48 = (ART_NODE48*)new;
            // Initialize child_index to 0 to avoid stale values
            RtlZeroMemory(new48->child_index, sizeof(new48->child_index));
            for (i = 0; i < old->num_of_child; i++) {
                new48->child_index[old16->keys[i]] = (UCHAR)(i + 1);
                new48->children[i] = old16->children[i];
            }
        }
        break;
    }
    case NODE48: {
        ART_NODE48* old48 = (ART_NODE48*)old;
        if (new_type == NODE256) {
            ART_NODE256* new256 = (ART_NODE256*)new;
            for (i = 0; i < 256; i++) {
                if (old48->child_index[i]) {
                    new256->children[i] = old48->children[old48->child_index[i] - 1];
                }
            }
        }
        break;
    }
    }
    new->num_of_child = old->num_of_child;
    ExFreePoolWithTag(old, ART_TAG);
    *node_ref = new;
}

BOOLEAN art_insert_child(ART_NODE** node_ref, UCHAR path_byte, ART_NODE* child) {
    if (!node_ref || !(*node_ref)) {
        return FALSE;
    }

    ART_NODE* node = *node_ref;

    switch (node->type) {
    case NODE4: {
        ART_NODE4* node4 = (ART_NODE4*)node;
        if (node->num_of_child < 4) {
            node4->keys[node->num_of_child] = path_byte;
            node4->children[node->num_of_child] = child;
            node->num_of_child++;
        }
        else {
            // Upgrade NODE4 to NODE16
            art_upgrade_node(node_ref, NODE16);
            node = *node_ref;
            ART_NODE16* node16 = (ART_NODE16*)node;
            node16->keys[node->num_of_child] = path_byte;
            node16->children[node->num_of_child] = child;
            node->num_of_child++;
        }
        break;
    }
    case NODE16: {
        ART_NODE16* node16 = (ART_NODE16*)node;
        if (node->num_of_child < 16) {
            node16->keys[node->num_of_child] = path_byte;
            node16->children[node->num_of_child] = child;
            node->num_of_child++;
        }
        else {
            // Upgrade NODE16 to NODE48
            art_upgrade_node(node_ref, NODE48);
            node = *node_ref;
            ART_NODE48* node48 = (ART_NODE48*)node;
            node48->child_index[path_byte] = (UCHAR)(node->num_of_child + 1);
            node48->children[node->num_of_child] = child;
            node->num_of_child++;
        }
        break;
    }
    case NODE48: {
        ART_NODE48* node48 = (ART_NODE48*)node;
        if (node->num_of_child < 48) {
            node48->child_index[path_byte] = (UCHAR)(node->num_of_child + 1);
            node48->children[node->num_of_child] = child;
            node->num_of_child++;
        }
        else {
            // Upgrade NODE48 to NODE256
            art_upgrade_node(node_ref, NODE256);
            node = *node_ref;
            ART_NODE256* node256 = (ART_NODE256*)node;
            node256->children[path_byte] = child;
            node->num_of_child++;
        }
        break;
    }
    case NODE256: {
        ART_NODE256* node256 = (ART_NODE256*)node;
        if (!node256->children[path_byte]) {
            node->num_of_child++;
        }
        node256->children[path_byte] = child;
        break;
    }
    default:
        return FALSE;
    }

    return TRUE;
}

static USHORT common_prefix_length(PCUCHAR path1, USHORT path1_length, PCUCHAR path2, USHORT path2_length) {
    USHORT length = (path1_length < path2_length) ? path1_length : path2_length;
    USHORT i;
    for (i = 0; i < length; i++) {
        if (path1[i] != path2[i]) {
            return i;
        }
    }
    return i;
}

ART_NODE* art_find_child_prefix(ART_NODE* node, PCUCHAR path_bytes, USHORT path_length, USHORT* path_cursor) {
    if (!node || !path_bytes || !path_cursor || *path_cursor > path_length) {
        return NULL;
    }

    USHORT cursor = *path_cursor;

    USHORT longest_common_prefix_length = common_prefix_length(node->prefix, node->prefix_length, path_bytes + cursor, (path_length - cursor));
    if (longest_common_prefix_length != node->prefix_length) {
        // Prefix does not match fully, no child
        return NULL;
    }

    cursor += longest_common_prefix_length;
    if (cursor == path_length) {
        // Key fully matched at this node, no next child
        *path_cursor = cursor;
        return node;
    }

    // Lookup child for next path byte after prefix
    UCHAR next_path = path_bytes[cursor];
    ART_NODE* child = NULL;

    switch (node->type) {
    case NODE4: {
        ART_NODE4* n = (ART_NODE4*)node;
        for (USHORT i = 0; i < node->num_of_child; i++) {
            if (n->keys[i] == next_path) {
                child = n->children[i];
                break;
            }
        }
        break;
    }
    case NODE16: {
        ART_NODE16* n = (ART_NODE16*)node;
        for (USHORT i = 0; i < node->num_of_child; i++) {
            if (n->keys[i] == next_path) {
                child = n->children[i];
                break;
            }
        }
        break;
    }
    case NODE48: {
        ART_NODE48* n = (ART_NODE48*)node;
        if (n->child_index[next_path]) {
            child = n->children[n->child_index[next_path] - 1];
        }
        break;
    }
    case NODE256: {
        ART_NODE256* n = (ART_NODE256*)node;
        child = n->children[next_path];
        break;
    }
    default:
        return NULL;
    }

    if (child) {
        *path_cursor = cursor + 1; // move past this byte
    }

    return child;
}

BOOLEAN art_insert(ART_NODE** root_ref, PCUNICODE_STRING unicode_path, ACCESS_MASK access_mask) {
    if (!root_ref || !(*root_ref) || !unicode_path || !unicode_path->Buffer) {
        return FALSE;
    }

    PUCHAR path_bytes = ExAllocatePool2(POOL_FLAG_NON_PAGED, unicode_path->MaximumLength, ART_TAG);
    if (!path_bytes) {
        return FALSE;
    }

    if (unicode_to_utf8(unicode_path, path_bytes, sizeof(path_bytes), NULL)) {
        return FALSE;
    }

    ART_NODE* current = *root_ref;
    USHORT path_length = sizeof(path_bytes)/ sizeof(WCHAR);
    USHORT path_cursor = 0;

    while (path_cursor < path_length) {
        USHORT long_common_prefix_length = common_prefix_length(current->prefix, current->prefix_length, path_bytes + path_cursor, (USHORT)(path_length - path_cursor));

        if (long_common_prefix_length != 0 && long_common_prefix_length < current->prefix_length) {
            // Split node

            // Create new intermediate node with common prefix
            ART_NODE* new_node = art_create_node(NODE4);
            if (!new_node) {
                return FALSE;
            }
            new_node->prefix_length = long_common_prefix_length;
            RtlCopyMemory(new_node->prefix, current->prefix, long_common_prefix_length);
            new_node->is_end = FALSE;

            // Adjust old node's prefix to suffix after long common prefix
            USHORT old_suffix_length = current->prefix_length - long_common_prefix_length;
            for (USHORT i = 0; i < old_suffix_length; i++) {
                current->prefix[i] = current->prefix[long_common_prefix_length + i];
            }
            current->prefix_length = old_suffix_length;

            // Insert old node as child of new node with path = old prefix first byte
            if (!art_insert_child(&new_node, current->prefix[0], current)) {
                ExFreePoolWithTag(new_node, ART_TAG);
                return FALSE;
            }

            *root_ref = new_node;
            current = new_node;
        }

        path_cursor += long_common_prefix_length;
        if (path_cursor == path_length) {
            // path fully consumed, mark current node as end and set rights
            current->is_end = TRUE;
            current->access_rights = access_mask;
            return TRUE;
        }

        // After prefix handling, if there's still path remaining, find or create the child for the next byte
        if (path_cursor >= path_length) {
            break;
        }

        UCHAR next_path = path_bytes[path_cursor];
        ART_NODE* child = art_find_child_prefix(current, path_bytes, path_length, &path_cursor);
        if (!child) {
            // Create new leaf node with remaining path as prefix
            ART_NODE* leaf = art_create_node(NODE4);
            if (!leaf) {
                return FALSE;
            }
            leaf->prefix_length = (USHORT)(path_length - path_cursor);
            RtlCopyMemory(leaf->prefix, path_bytes + path_cursor, leaf->prefix_length);
            leaf->is_end = TRUE;
            leaf->access_rights = access_mask;

            if (!art_insert_child(&current, next_path, leaf)) {
                ExFreePoolWithTag(leaf, ART_TAG);
                return FALSE;
            }
            return TRUE;
        }

        // Child found, continue traversal
        current = child;
    }

    current->is_end = TRUE;
    current->access_rights = access_mask;
    return TRUE;
}

BOOLEAN art_search(ART_NODE* root, PCUNICODE_STRING unicode_path, ACCESS_MASK* out_access_rights) {
    if (!root || !unicode_path || !unicode_path->Buffer || !out_access_rights) {
        return FALSE;
    }

    PUCHAR path_bytes = ExAllocatePool2(POOL_FLAG_NON_PAGED, unicode_path->MaximumLength, ART_TAG);
    if (!path_bytes) {
        return FALSE;
    }

    if (unicode_to_utf8(unicode_path, path_bytes, sizeof(path_bytes), NULL)) {
        return FALSE;
    }

    ART_NODE* current = root;
    USHORT path_length = sizeof(path_bytes) / sizeof(WCHAR);
    USHORT path_cursor = 0;

    while (current) {
        ART_NODE* next = art_find_child_prefix(current, path_bytes, path_length, &path_cursor);

        if (!next) {
            return FALSE;
        }

        if (path_cursor == path_length) {
            if (next->is_end) {
                *out_access_rights = next->access_rights;
                return TRUE;
            }
            return FALSE;
        }
        current = next;
    }

    return FALSE;
}

VOID art_free_node(ART_NODE* node) {
    if (!node) {
        return;
    }

    switch (node->type) {
        case NODE4: {
            ART_NODE4* n = (ART_NODE4*)node;
            for (USHORT i = 0; i < node->num_of_child; i++) {
                art_free_node(n->children[i]);
            }
            break;
        }
        case NODE16: {
            ART_NODE16* n = (ART_NODE16*)node;
            for (USHORT i = 0; i < node->num_of_child; i++) {
                art_free_node(n->children[i]);
            }
            break;
        }
        case NODE48: {
            ART_NODE48* n = (ART_NODE48*)node;
            for (USHORT i = 0; i < 256; i++) {
                if (n->child_index[i]) {
                    art_free_node(n->children[n->child_index[i] - 1]);
                }
            }
            break;
        }
        case NODE256: {
            ART_NODE256* n = (ART_NODE256*)node;
            for (USHORT i = 0; i < 256; i++) {
                art_free_node(n->children[i]);
            }
            break;
        }
    }
    ExFreePoolWithTag(node, ART_TAG);
}
