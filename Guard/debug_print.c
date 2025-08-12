#include "test_art.h"

#define MAX_PRINT_DEPTH 32
#define INDENT_SIZE 2
#define MAX_KEY_PRINT_LENGTH 256

static VOID print_indent_with_tree_lines(USHORT depth, BOOLEAN is_last_child) {
    if (depth == 0) return;

    // Print tree structure lines for better visualization
    for (USHORT i = 0; i < depth - 1; i++) {
        LOG_MSG("|  ");  // Vertical line for parent levels
    }

    if (is_last_child) {
        LOG_MSG("|_");  // Last child marker
    }
    else {
        LOG_MSG("|-");  // Regular child marker
    }
}

static VOID print_key_safe(_In_reads_bytes_opt_(len) CONST UCHAR* key, _In_ ULONG len) {
    if (!key || len == 0) {
        LOG_MSG("(empty)");
        return;
    }

    // Limit print length to avoid excessive output
    ULONG print_len = min(len, MAX_KEY_PRINT_LENGTH);
    BOOLEAN truncated = (len > MAX_KEY_PRINT_LENGTH);

    for (ULONG i = 0; i < print_len; i++) {
        unsigned char c = key[i];
        if (c >= 32 && c <= 126 && c != '\\' && c != '"') {
            // ASCII printable range, excluding special characters
            LOG_MSG("%c", c);
        }
        else {
            // Non-printable or special characters
            switch (c) {
            case '\0': LOG_MSG("\\0"); break;
            case '\n': LOG_MSG("\\n"); break;
            case '\r': LOG_MSG("\\r"); break;
            case '\t': LOG_MSG("\\t"); break;
            case '\\': LOG_MSG("\\\\"); break;
            case '"':  LOG_MSG("\\\""); break;
            default:   LOG_MSG("\\x%02x", c); break;
            }
        }
    }

    if (truncated) {
        LOG_MSG("...[+%lu more]", len - print_len);
    }
}

static VOID print_char_enhanced(unsigned char c) {
    if (c >= 32 && c <= 126) {
        LOG_MSG("'%c'", c);
    }
    else {
        switch (c) {
        case '\0': LOG_MSG("'\\0'"); break;
        case '\n': LOG_MSG("'\\n'"); break;
        case '\r': LOG_MSG("'\\r'"); break;
        case '\t': LOG_MSG("'\\t'"); break;
        default:   LOG_MSG("0x%02x", c); break;
        }
    }
}

static BOOLEAN validate_node_for_print(_In_opt_ ART_NODE* node, _In_ USHORT depth) {
    if (depth > MAX_PRINT_DEPTH) {
        LOG_MSG("[ERROR: Max print depth exceeded - possible circular reference]\n");
        return FALSE;
    }

    if (!node) {
        return TRUE; // NULL is valid
    }

    // Basic node type validation
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            LOG_MSG("[ERROR: Invalid leaf node - NULL leaf data]\n");
            return FALSE;
        }
        if (leaf->key_length > 0 && !leaf->key) {
            LOG_MSG("[ERROR: Invalid leaf - non-zero length but NULL key]\n");
            return FALSE;
        }
        return TRUE;
    }

    // Internal node validation
    if (node->type < NODE4 || node->type > NODE256) {
        LOG_MSG("[ERROR: Invalid node type: %d]\n", node->type);
        return FALSE;
    }

    if (node->prefix_length > MAX_PREFIX_LENGTH) {
        LOG_MSG("[ERROR: Invalid prefix length: %d]\n", node->prefix_length);
        return FALSE;
    }

    return TRUE;
}

static VOID print_art_node_enhanced(_In_opt_ ART_NODE* node, _In_ USHORT depth, _In_ BOOLEAN is_last_child) {
    if (!validate_node_for_print(node, depth)) {
        return;
    }

    if (!node) {
        print_indent_with_tree_lines(depth, is_last_child);
        LOG_MSG("(null)\n");
        return;
    }

    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        print_indent_with_tree_lines(depth, is_last_child);
        LOG_MSG("Leaf: key=\"");
        print_key_safe(leaf->key, leaf->key_length);
        LOG_MSG("\" len=%llu, value=%p\n", leaf->key_length, leaf->value);
        return;
    }

    // Print internal node header with enhanced formatting
    print_indent_with_tree_lines(depth, is_last_child);

    // Node type emoji for better visibility
    const char* node_emoji;
    switch (node->type) {
    case NODE4:   node_emoji = "NODE4"; break;  // Small node
    case NODE16:  node_emoji = "NODE16"; break;  // Medium node  
    case NODE48:  node_emoji = "NODE48"; break;  // Large node
    case NODE256: node_emoji = "NODE256"; break;  // Very large node
    default:      node_emoji = "NODE?"; break;  // Unknown
    }

    LOG_MSG("%s Node%d: children=%d", node_emoji, node->type, node->num_of_child);

    if (node->prefix_length > 0) {
        LOG_MSG(", prefix[%d]=\"", node->prefix_length);
        print_key_safe(node->prefix, node->prefix_length);
        LOG_MSG("\"");
    }

    LOG_MSG("\n");

    // Print children with proper bounds checking
    switch (node->type) {
    case NODE4: {
        ART_NODE4* node4 = (ART_NODE4*)node;
        USHORT safe_child_count = min(node4->base.num_of_child, 4);

        for (USHORT i = 0; i < safe_child_count; i++) {
            if (node4->children[i]) {
                print_indent_with_tree_lines(depth + 1, FALSE);
                LOG_MSG("key=");
                print_char_enhanced(node4->keys[i]);
                LOG_MSG(":\n");
                print_art_node_enhanced(node4->children[i], depth + 2, (i == safe_child_count - 1));
            }
            else {
                print_indent_with_tree_lines(depth + 1, FALSE);
                LOG_MSG("key=");
                print_char_enhanced(node4->keys[i]);
                LOG_MSG(": (null child)\n");
            }
        }
        break;
    }

    case NODE16: {
        ART_NODE16* node16 = (ART_NODE16*)node;
        USHORT safe_child_count = min(node16->base.num_of_child, 16);

        for (USHORT i = 0; i < safe_child_count; i++) {
            if (node16->children[i]) {
                print_indent_with_tree_lines(depth + 1, FALSE);
                LOG_MSG("key=");
                print_char_enhanced(node16->keys[i]);
                LOG_MSG(":\n");
                print_art_node_enhanced(node16->children[i], depth + 2, (i == safe_child_count - 1));
            }
            else {
                print_indent_with_tree_lines(depth + 1, FALSE);
                LOG_MSG("key=");
                print_char_enhanced(node16->keys[i]);
                LOG_MSG(": (null child)\n");
            }
        }
        break;
    }

    case NODE48: {
        ART_NODE48* node48 = (ART_NODE48*)node;
        USHORT printed_children = 0;

        for (USHORT i = 0; i < 256; i++) {
            UCHAR pos = node48->child_index[i];
            if (pos > 0 && pos <= 48) {
                ART_NODE* child = node48->children[pos - 1];
                if (child) {
                    print_indent_with_tree_lines(depth + 1, FALSE);
                    LOG_MSG("key=");
                    print_char_enhanced((unsigned char)i);
                    LOG_MSG(" [pos=%d]:\n", pos - 1);
                    print_art_node_enhanced(child, depth + 2,
                        (printed_children == node48->base.num_of_child - 1));
                    printed_children++;
                }
                else {
                    print_indent_with_tree_lines(depth + 1, FALSE);
                    LOG_MSG("key=");
                    print_char_enhanced((unsigned char)i);
                    LOG_MSG(" [pos=%d]: (null child - ERROR)\n", pos - 1);
                }
            }
        }
        break;
    }

    case NODE256: {
        ART_NODE256* node256 = (ART_NODE256*)node;
        USHORT printed_children = 0;

        for (USHORT i = 0; i < 256; i++) {
            if (node256->children[i]) {
                print_indent_with_tree_lines(depth + 1, FALSE);
                LOG_MSG("key=");
                print_char_enhanced((unsigned char)i);
                LOG_MSG(":\n");
                print_art_node_enhanced(node256->children[i], depth + 2,
                    (printed_children == node256->base.num_of_child - 1));
                printed_children++;
            }
        }
        break;
    }

    default:
        print_indent_with_tree_lines(depth + 1, FALSE);
        LOG_MSG("ERROR: Unknown node type %d\n", node->type);
        break;
    }
}

static VOID count_nodes_with_stats(_In_opt_ ART_NODE* node, _Inout_ PULONG total_count,
    _Inout_ PULONG leaf_count, _Inout_ PULONG internal_count,
    _Inout_ PULONG node_type_counts, _Inout_ PUSHORT max_depth,
    _In_ USHORT current_depth) {
    if (!node) return;

    (*total_count)++;

    if (current_depth > *max_depth) {
        *max_depth = current_depth;
    }

    if (IS_LEAF(node)) {
        (*leaf_count)++;
        node_type_counts[4]++; // LEAF index
        return;
    }

    (*internal_count)++;

    // Count by node type
    switch (node->type) {
    case NODE4:   node_type_counts[0]++; break;
    case NODE16:  node_type_counts[1]++; break;
    case NODE48:  node_type_counts[2]++; break;
    case NODE256: node_type_counts[3]++; break;
    }

    // Recursively count children
    switch (node->type) {
    case NODE4: {
        ART_NODE4* node4 = (ART_NODE4*)node;
        for (USHORT i = 0; i < min(node4->base.num_of_child, 4); i++) {
            count_nodes_with_stats(node4->children[i], total_count, leaf_count,
                internal_count, node_type_counts, max_depth, current_depth + 1);
        }
        break;
    }
    case NODE16: {
        ART_NODE16* node16 = (ART_NODE16*)node;
        for (USHORT i = 0; i < min(node16->base.num_of_child, 16); i++) {
            count_nodes_with_stats(node16->children[i], total_count, leaf_count,
                internal_count, node_type_counts, max_depth, current_depth + 1);
        }
        break;
    }
    case NODE48: {
        ART_NODE48* node48 = (ART_NODE48*)node;
        for (USHORT i = 0; i < 256; i++) {
            UCHAR pos = node48->child_index[i];
            if (pos > 0 && pos <= 48 && node48->children[pos - 1]) {
                count_nodes_with_stats(node48->children[pos - 1], total_count, leaf_count,
                    internal_count, node_type_counts, max_depth, current_depth + 1);
            }
        }
        break;
    }
    case NODE256: {
        ART_NODE256* node256 = (ART_NODE256*)node;
        for (USHORT i = 0; i < 256; i++) {
            if (node256->children[i]) {
                count_nodes_with_stats(node256->children[i], total_count, leaf_count,
                    internal_count, node_type_counts, max_depth, current_depth + 1);
            }
        }
        break;
    }
    }
}

static VOID print_tree_statistics(_In_ ART_TREE* tree) {
    if (!tree) {
        LOG_MSG("Tree Statistics: (null tree)\n");
        return;
    }

    ULONG actual_size = 0;
    ULONG leaf_count = 0;
    ULONG internal_count = 0;
    ULONG node_type_counts[5] = { 0 }; // NODE4, NODE16, NODE48, NODE256, LEAF
    USHORT max_depth = 0;

    // Count nodes and gather statistics
    count_nodes_with_stats(tree->root, &actual_size, &leaf_count, &internal_count,
        node_type_counts, &max_depth, 0);

    LOG_MSG("Tree Statistics:\n");
    LOG_MSG("   Total size: %llu (reported: %lu)%s\n", actual_size, tree->size, (actual_size != tree->size) ? "MISMATCH!" : " ");
    LOG_MSG("   Leaf nodes: %lu\n", leaf_count);
    LOG_MSG("   Internal nodes: %lu\n", internal_count);
    LOG_MSG("   |_ NODE4:   %lu\n", node_type_counts[0]);
    LOG_MSG("   |_ NODE16:  %lu\n", node_type_counts[1]);
    LOG_MSG("   |_ NODE48:  %lu\n", node_type_counts[2]);
    LOG_MSG("   |_ NODE256: %lu\n", node_type_counts[3]);
    LOG_MSG("   Maximum depth: %d\n", max_depth);

    if (tree->root) {
        LOG_MSG("   Root node type: NODE%d\n",
            IS_LEAF(tree->root) ? 0 : tree->root->type);
    }
    else {
        LOG_MSG("   Root: (null) - Empty tree\n");
    }
}

VOID art_print_tree(_In_opt_ ART_TREE* tree) {
    if (!tree) {
        LOG_MSG("\n\nART Tree: (null tree pointer)\n");
        return;
    }

    LOG_MSG("\n========== ART Tree Debug Dump ==========\n");
    print_tree_statistics(tree);
    LOG_MSG("Tree Structure:\n");

    if (!tree->root) {
        LOG_MSG("   (empty tree)\n");
    }
    else {
        print_art_node_enhanced(tree->root, 0, TRUE);
    }

    LOG_MSG("========== End of Tree Dump ===========\n\n");
}

VOID art_print_subtree(_In_opt_ ART_NODE* subtree_root, _In_z_ const char* description) {
    LOG_MSG("\n========== ART Subtree: %s ==========\n", description);

    if (!subtree_root) {
        LOG_MSG("   (null subtree)\n");
    }
    else {
        print_art_node_enhanced(subtree_root, 0, TRUE);
    }

    LOG_MSG("========== End of Subtree ==========\n\n");
}

BOOLEAN art_validate_tree_quick(_In_opt_ ART_TREE* tree) {
    if (!tree) {
        LOG_MSG("Tree validation failed: NULL tree\n");
        return FALSE;
    }

    ULONG actual_size = 0;
    ULONG leaf_count = 0;
    ULONG internal_count = 0;
    ULONG node_type_counts[5] = { 0 };
    USHORT max_depth = 0;

    count_nodes_with_stats(tree->root, &actual_size, &leaf_count, &internal_count,
        node_type_counts, &max_depth, 0);

    BOOLEAN size_matches = (actual_size == tree->size);
    BOOLEAN depth_reasonable = (max_depth < MAX_PRINT_DEPTH);

    if (size_matches && depth_reasonable) {
        LOG_MSG("Tree validation passed : size = % lu, depth = % d\n", actual_size, max_depth);
        return TRUE;
    }
    else {
        LOG_MSG("Tree validation failed: size_match=%d (actual=%llu, reported=%lu), depth_ok=%d (depth=%d)\n",
            size_matches, actual_size, tree->size, depth_reasonable, max_depth);
        return FALSE;
    }
}
