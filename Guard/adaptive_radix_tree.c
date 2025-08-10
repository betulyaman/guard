#include "adaptive_radix_tree.h"

#include "log.h"


ART_TREE g_art_tree;

#pragma warning(push)
#pragma warning(disable: 6101)
STATIC INLINE PUCHAR unicode_to_utf8(_In_ PCUNICODE_STRING unicode, _Out_ PUSHORT out_length)
{
    // do NOT touch out_length on bad-arg early exits (tests expect that)
    if (!unicode || !out_length || !unicode->Buffer || unicode->Length == 0) {
        return NULL;
    }

    const ULONG char_count = unicode->Length / sizeof(WCHAR);
    if (char_count > 65535) {
        DbgPrint("[ART] unicode_to_utf8: path too long (%lu chars)\n", char_count);
        return NULL;
    }

    *out_length = 0; // safe default for all normal processing/hot paths

    // Lowercase copy
    UNICODE_STRING lower_unicode;
    RtlInitEmptyUnicodeString(&lower_unicode, NULL, 0);

    lower_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, unicode->Length, ART_TAG);
    if (!lower_unicode.Buffer) {
        *out_length = 0; // ensure output param initialized
        return NULL;
    }
    lower_unicode.MaximumLength = unicode->Length;
    lower_unicode.Length = 0;

    NTSTATUS status = RtlDowncaseUnicodeString(&lower_unicode, unicode, FALSE);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(lower_unicode.Buffer, ART_TAG);
        *out_length = 0;
        return NULL;
    }

    // Probe required UTF-8 length
    ULONG required_length = 0;
    status = RtlUnicodeToUTF8N(NULL, 0, &required_length, lower_unicode.Buffer, lower_unicode.Length);
    if (!NT_SUCCESS(status) || required_length == 0) {
        ExFreePoolWithTag(lower_unicode.Buffer, ART_TAG);
        *out_length = 0;
        return NULL;
    }

    // Guard: do not exceed overall limits
    if (required_length > MAX_KEY_LENGTH || required_length > USHRT_MAX) {
        LOG_MSG("unicode_to_utf8: key length %lu exceeds limits (MAX_KEY_LENGTH=%u, USHRT_MAX=%u)",
            required_length, (unsigned)MAX_KEY_LENGTH, (unsigned)USHRT_MAX);
        ExFreePoolWithTag(lower_unicode.Buffer, ART_TAG);
        *out_length = 0;
        return NULL;
    }

    const SIZE_T alloc_size = (SIZE_T)required_length + 1;
    PUCHAR utf8_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, ART_TAG);
    if (!utf8_key) {
        ExFreePoolWithTag(lower_unicode.Buffer, ART_TAG);
        *out_length = 0;
        return NULL;
    }

    ULONG written_length = 0;
    status = RtlUnicodeToUTF8N((PCHAR)utf8_key, required_length, &written_length,
        lower_unicode.Buffer, lower_unicode.Length);

    ExFreePoolWithTag(lower_unicode.Buffer, ART_TAG);

    if (!NT_SUCCESS(status) || written_length == 0 || written_length > required_length) {
        LOG_MSG("unicode_to_utf8: RtlUnicodeToUTF8N failed (st=0x%x, w=%lu, req=%lu)",
            status, written_length, required_length);
        ExFreePoolWithTag(utf8_key, ART_TAG);
        *out_length = 0;
        return NULL;
    }

    // USHORT safety (already guarded above)
    utf8_key[written_length] = '\0';
    *out_length = (USHORT)written_length;

    return utf8_key;
}
#pragma warning(pop)

STATIC INLINE VOID destroy_utf8_key(_In_opt_ PUCHAR key)
{
    if (key) {
#ifdef DEBUG
        LOG_MSG("destroy_utf8_key: freeing UTF-8 key at %p", key);
#endif
        ExFreePoolWithTag(key, ART_TAG);
    }
}

STATIC INLINE VOID free_node(_Inout_ ART_NODE** node)
{
    if (node && *node) {
        LOG_MSG("free_node: freeing node at %p (type: %d)", *node, (*node)->type);
#ifdef DEBUG
        (*node)->type = (NODE_TYPE)0xFF; // poison in debug
#endif
        ExFreePoolWithTag(*node, ART_TAG);
        *node = NULL;
    }
}

STATIC INLINE VOID free_leaf(_Inout_ ART_LEAF** leaf)
{
    if (leaf && *leaf) {
#ifdef DEBUG
        if ((*leaf)->key_length == LEAF_FREED_MAGIC) {
            DbgPrint("[ART][WARN] double free attempt for leaf %p\n", *leaf);
            DbgBreakPoint(); // signal double-free in debug (tests count this)
        }
        else {
            (*leaf)->key_length = LEAF_FREED_MAGIC; // poison in debug before free
        }
#endif
        LOG_MSG("free_leaf: freeing leaf at %p", *leaf);
        ExFreePoolWithTag(*leaf, ART_TAG);
        *leaf = NULL;
    }
}

STATIC ART_NODE* art_create_node(_In_ NODE_TYPE type)
{
    SIZE_T size = 0;
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
        LOG_MSG("art_create_node: Invalid node type %d", type);
        return NULL;
    }


    ART_NODE* node = (ART_NODE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, ART_TAG);
    if (!node) {
        LOG_MSG("art_create_node: Allocation failed for size %I64u", size);
        return NULL;
    }

    RtlZeroMemory(node, size);
    node->prefix_length = 0;
    node->type = type;
    node->num_of_child = 0;

    return node;
}

NTSTATUS art_init_tree(ART_TREE* tree)
{
    if (!tree) {
        return STATUS_INVALID_PARAMETER;
    }

    tree->root = NULL;
    tree->size = 0;
    return STATUS_SUCCESS;
}

/** COMMON Local Functions */
STATIC BOOLEAN leaf_matches(CONST ART_LEAF* leaf, CONST PUCHAR key, SIZE_T key_length) {

    if (!leaf
        || !key
        || key_length == 0
        || key_length > MAX_KEY_LENGTH
        || !leaf->key
        || leaf->key_length == 0) {
        return FALSE;
    }

    // Fail if the key lengths are different
    if (leaf->key_length != (UINT32)key_length) {
        return FALSE;
    }

    SIZE_T matching_length = RtlCompareMemory(leaf->key, key, key_length);
    return (matching_length == key_length);
}

// Count Trailing Zeros - finds the lowest set bit
STATIC INLINE unsigned int ctz(UINT32 x) {
    unsigned long index = 0;

    if (x == 0) {
        return 32; // Safe guard
    }

    if (_BitScanForward(&index, x)) {
        return (unsigned)index;
    }

    return 32;
}

STATIC ART_NODE** find_child(_In_ ART_NODE* node, _In_ UCHAR c)
{
    if (!node) {
        return NULL;
    }

    switch (node->type) {
    case NODE4: {
        ART_NODE4* node4 = (ART_NODE4*)node;
        USHORT safe_child_count = min(node->num_of_child, 4);
        for (USHORT i = 0; i < safe_child_count; i++) {
            if (node4->keys[i] == c) {
                return &node4->children[i];
            }
        }
        break;
    }

    case NODE16: {
        ART_NODE16* node16 = (ART_NODE16*)node;
        USHORT safe_child_count = min(node->num_of_child, 16);

        for (USHORT i = 0; i < safe_child_count; i++) {
            if (node16->keys[i] == c) {
                return &node16->children[i];
            }
        }
        break;
    }

    case NODE48: {
        ART_NODE48* node48 = (ART_NODE48*)node;
        int index = node48->child_index[c]; // 1..48
        if (index > 0 && index <= 48) {
            if (node48->children[index - 1]) {
                return &node48->children[index - 1];
            }
        }
        break;
    }

    case NODE256: {
        ART_NODE256* node256 = (ART_NODE256*)node;
        if (node256->children[c]) {
            return &node256->children[c];
        }
        break;
    }

    default:
        LOG_MSG("find_child: Invalid node type %d", node->type);
        break;
    }

    return NULL;
}

STATIC NTSTATUS copy_header(_Inout_ ART_NODE* dest, _In_ ART_NODE* src)
{
    if (!dest || !src) {
        LOG_MSG("copy_header: NULL parameter detected");
        return STATUS_INVALID_PARAMETER;
    }

    dest->num_of_child = src->num_of_child;

    if (src->prefix_length == 0) {
        dest->prefix_length = 0;
        return STATUS_SUCCESS;
    }

    const USHORT copy_length = (USHORT)min(src->prefix_length, MAX_PREFIX_LENGTH);
    if (copy_length) {
        RtlCopyMemory(dest->prefix, src->prefix, copy_length);
    }
    dest->prefix_length = copy_length;

    return STATUS_SUCCESS;
}

STATIC USHORT check_prefix(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth)
{
    if (!node || !key || depth >= key_length || key_length > MAX_KEY_LENGTH) {
        return 0;
    }

    if (depth > MAX_TREE_DEPTH) {
        LOG_MSG("check_prefix: Excessive depth %u detected", depth);
        return 0;
    }

    if (node->prefix_length == 0) {
        return 0;
    }

    USHORT safe_prefix_length = min(node->prefix_length, MAX_PREFIX_LENGTH);
    USHORT remaining_key_length = key_length - depth;
    USHORT maximum_compare_length = min(safe_prefix_length, remaining_key_length);

    if (maximum_compare_length == 0) {
        return 0;
    }

    for (USHORT index = 0; index < maximum_compare_length; index++) {

        if (node->prefix[index] != key[depth + index]) {
            return index;
        }
    }

    return maximum_compare_length;
}

/** INSERT Functions */

STATIC ART_LEAF* minimum(CONST ART_NODE* node) {
    if (!node) {
        return NULL;
    }

    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    if (node->type < NODE4 || node->type > NODE256) {
        LOG_MSG("Invalid NODE type in minimum()");
        return NULL;
    }

    if (node->num_of_child == 0) {
        LOG_MSG("Node has no children in minimum()");
        return NULL;
    }

    switch (node->type) {
    case NODE4: {
        // For NODE4, children are sorted by key order
        // First non-NULL child is the minimum
        CONST ART_NODE4* node4 = (CONST ART_NODE4*)node;
        USHORT limit = min(node->num_of_child, 4);
        for (USHORT i = 0; i < limit; i++) {
            if (node4->children[i]) {
                return minimum(node4->children[i]);
            }
        }
        break;
    }

    case NODE16: {
        // For NODE16, children are sorted by key order  
        // First non-NULL child is the minimum
        CONST ART_NODE16* node16 = (CONST ART_NODE16*)node;
        USHORT limit = min(node->num_of_child, 16);
        for (USHORT i = 0; i < limit; i++) {
            if (node16->children[i]) {
                return minimum(node16->children[i]);
            }
        }
        break;
    }

    case NODE48: {
        // NODE48 uses child_index array to map byte values to child indices
        CONST ART_NODE48* node48 = (CONST ART_NODE48*)node;
        for (int i = 0; i < 256; i++) {
            if (node48->child_index[i]) {
                int child_idx = node48->child_index[i] - 1;
                if (child_idx >= 0 && child_idx < 48) {
                    if (node48->children[child_idx]) {
                        return minimum(node48->children[child_idx]);
                    }
                }
            }
        }
        break;
    }

    case NODE256: {
        // NODE256 directly maps byte values to children
        CONST ART_NODE256* node256 = (CONST ART_NODE256*)node;
        for (int i = 0; i < 256; i++) {
            if (node256->children[i]) {
                return minimum(node256->children[i]);
            }
        }
        break;
    }

    default:
        LOG_MSG("Invalid NODE type in minimum()");
        break;
    }

    LOG_MSG("No valid child found in minimum()");
    return NULL;
}

STATIC ART_LEAF* maximum(CONST ART_NODE* node) {
    if (!node) {
        return NULL;
    }

    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    if (node->type < NODE4 || node->type > NODE256) {
        LOG_MSG("Invalid NODE type in maximum()");
        return NULL;
    }

    if (node->num_of_child == 0) {
        LOG_MSG("Node has no children in maximum()");
        return NULL;
    }

    switch (node->type) {
    case NODE4: {
        // For NODE4, last child has maximum key
        CONST ART_NODE4* node4 = (CONST ART_NODE4*)node;
        USHORT limit = min(node->num_of_child, 4);
        for (int i = (int)limit - 1; i >= 0; i--) {
            if (node4->children[i]) {
                return maximum(node4->children[i]);
            }
        }
        break;
    }

    case NODE16: {
        CONST ART_NODE16* node16 = (CONST ART_NODE16*)node;
        USHORT limit = min(node->num_of_child, 16);
        for (int i = (int)limit - 1; i >= 0; i--) {
            if (node16->children[i]) {
                return maximum(node16->children[i]);
            }
        }
        break;
    }

    case NODE48: {
        CONST ART_NODE48* node48 = (CONST ART_NODE48*)node;
        for (int i = 255; i >= 0; i--) {
            if (node48->child_index[i]) {
                int child_idx = node48->child_index[i] - 1;
                if (child_idx >= 0 && child_idx < 48) {
                    if (node48->children[child_idx]) {
                        return maximum(node48->children[child_idx]);
                    }
                }
            }
        }
        break;
    }

    case NODE256: {
        CONST ART_NODE256* node256 = (CONST ART_NODE256*)node;
        for (int i = 255; i >= 0; i--) {
            if (node256->children[i]) {
                return maximum(node256->children[i]);
            }
        }
        break;
    }

    default:
        LOG_MSG("Invalid NODE type in maximum()");
        break;
    }

    LOG_MSG("No valid child found in maximum()");
    return NULL;
}

ART_LEAF* art_minimum(ART_TREE* tree) {
    if (!tree) {
        LOG_MSG("NULL tree passed to art_minimum()");
        return NULL;
    }

    if (!tree->root) {
        return NULL;
    }

    return minimum((ART_NODE*)tree->root);
}

ART_LEAF* art_maximum(ART_TREE* tree) {
    if (!tree) {
        LOG_MSG("NULL tree passed to art_maximum()");
        return NULL;
    }

    if (!tree->root) {
        // Empty tree  
        return NULL;
    }

    return maximum((ART_NODE*)tree->root);
}

STATIC ART_LEAF* make_leaf(CONST PUCHAR key, USHORT key_length, ULONG value) {
    if ((!key && key_length > 0) || key_length > MAX_KEY_LENGTH) {
        LOG_MSG("make_leaf: Invalid key or length (key=%p, length=%u)", key, key_length);
        return NULL;
    }

    // Check for integer overflow in allocation size calculation
    SIZE_T alloc_size = sizeof(ART_LEAF) + key_length;
    if (alloc_size < sizeof(ART_LEAF) || alloc_size < key_length) {
        LOG_MSG("make_leaf: Allocation size overflow");
        return NULL;
    }

    ART_LEAF* leaf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, ART_TAG);
    if (!leaf) {
        LOG_MSG("make_leaf: Memory allocation failed");
        return NULL;
    }

    RtlZeroMemory(leaf, alloc_size);
    leaf->value = value;
    leaf->key_length = key_length;

    if (key_length > 0 && key) {
        RtlCopyMemory(leaf->key, key, key_length);
    }

    return leaf;
}

STATIC USHORT longest_common_prefix(CONST ART_LEAF* leaf1, CONST ART_LEAF* leaf2, USHORT depth) {
    if (!leaf1 || !leaf2) {
        LOG_MSG("NULL leaf passed to longest_common_prefix()");
        return 0;
    }

    if (depth > leaf1->key_length || depth > leaf2->key_length) {
        LOG_MSG("Depth(%d) exceeds key length(%d || %d) in longest_common_prefix()", depth, leaf1->key_length, leaf2->key_length);
        return 0;
    }

    // Fixed: Changed >= instead of == for proper edge case handling
    if (depth >= leaf1->key_length || depth >= leaf2->key_length) {
        return 0;  // No common prefix when depth reaches or exceeds key length
    }

    USHORT min_remaining_length = min(leaf1->key_length - depth, leaf2->key_length - depth);

    // Bounds checking to prevent buffer overrun
    for (USHORT index = 0; index < min_remaining_length; index++) {
        USHORT pos1 = depth + index;
        USHORT pos2 = depth + index;

        // Additional safety check
        if (pos1 >= leaf1->key_length || pos2 >= leaf2->key_length) {
            break;
        }

        if (leaf1->key[pos1] != leaf2->key[pos2]) {
            return index;
        }
    }

    return min_remaining_length;
}

STATIC USHORT prefix_mismatch(CONST ART_NODE* node, CONST PUCHAR key, USHORT key_length, USHORT depth) {
    if (!node || !key) {
        LOG_MSG("NULL parameter passed to prefix_mismatch()");
        return 0;
    }

    if (depth > key_length) {
        LOG_MSG("Depth exceeds key length in prefix_mismatch()");
        return 0;
    }

    USHORT remaining_key_length = key_length - depth;
    if (remaining_key_length == 0) {
        return 0;
    }

    USHORT max_prefix_check = min(
        min(MAX_PREFIX_LENGTH, node->prefix_length),
        remaining_key_length
    );

    USHORT index = 0;
    for (; index < max_prefix_check; index++) {
        if (node->prefix[index] != key[depth + index]) {
            return index;
        }
    }

    // If node prefix is longer than MAX_PREFIX_LENGTH, we need to check more
    if (node->prefix_length > MAX_PREFIX_LENGTH) {
        // Find a leaf to get the full prefix
        CONST ART_LEAF* leaf = minimum(node);
        if (!leaf) {
            LOG_MSG("Could not find leaf for extended prefix check");
            return index;
        }

        // Check depth bounds for leaf
        if (depth > leaf->key_length) {
            LOG_MSG("Depth exceeds leaf key length in prefix_mismatch()");
            return index;
        }

        USHORT max_compare_length = min(
            min((USHORT)(leaf->key_length - depth), remaining_key_length),
            node->prefix_length
        );

        for (; index < max_compare_length; index++) {
            if (leaf->key[depth + index] != key[depth + index]) {
                return index;
            }
        }
    }

    return index;
}

STATIC NTSTATUS add_child256(_Inout_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child) {
    UNREFERENCED_PARAMETER(ref);

    if (!node || !child) {
        LOG_MSG("add_child256: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (node->base.type != NODE256) {
        LOG_MSG("add_child256: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    if (node->children[c] != NULL) {
        LOG_MSG("add_child256: Position %d already occupied", c);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    if (node->base.num_of_child >= 256) {
        LOG_MSG("add_child256: Node full, cannot add more children");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    node->base.num_of_child++;
    node->children[c] = (ART_NODE*)child;

    return STATUS_SUCCESS;
}

STATIC NTSTATUS add_child48(_Inout_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child) {
    if (!node || !ref || !child) {
        LOG_MSG("add_child48: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (node->base.type != NODE48) {
        LOG_MSG("add_child48: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    if (node->child_index[c] != 0) {
        LOG_MSG("add_child48: Key %d already exists", c);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    // If node has capacity, add child directly
    if (node->base.num_of_child < 48) {
        // Find first available slot
        UINT8 pos = 0;
        while (pos < 48 && node->children[pos] != NULL) {
            pos++;
        }

        if (pos >= 48) {
            LOG_MSG("add_child48: Inconsistent state - no free slots but count < 48");
            return STATUS_INTERNAL_ERROR;
        }

        node->children[pos] = (ART_NODE*)child;
        node->child_index[c] = pos + 1;  // +1 because 0 means empty
        node->base.num_of_child++;

        return STATUS_SUCCESS;
    }
    else {
        // Node is full, expand to NODE256
        ART_NODE256* new_node = (ART_NODE256*)art_create_node(NODE256);
        if (!new_node) {
            LOG_MSG("add_child48: Failed to create NODE256");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = STATUS_SUCCESS;

        // Copy header information first
        status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child48: Failed to copy header");
            goto cleanup_and_exit;
        }

        // Copy existing children to new node
        USHORT moved = 0;
        for (UINT16 i = 0; i < 256; i++) {
            if (node->child_index[i] != 0) {
                UINT8 child_pos = node->child_index[i] - 1;
                if (child_pos >= 48) {
                    LOG_MSG("add_child48: Invalid child index %d", child_pos);
                    status = STATUS_DATA_ERROR;
                    goto cleanup_and_exit;
                }
                new_node->children[i] = node->children[child_pos];
                moved++;
            }
        }

        new_node->base.num_of_child = moved;

        // Update reference before adding new child to prevent inconsistency
        ART_NODE* old_node = (ART_NODE*)node;
        *ref = (ART_NODE*)new_node;

        // Add the new child
        status = add_child256(new_node, ref, c, child);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child48: Failed to add child to new NODE256");
            *ref = old_node; // Rollback
            goto cleanup_and_exit;
        }

        // Free old node
        free_node(&old_node);
        return STATUS_SUCCESS;

    cleanup_and_exit:
        if (new_node) {
            free_node((ART_NODE**)&new_node);
        }
        return status;
    }
}

STATIC NTSTATUS add_child16(_Inout_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child) {
    // Input validation
    if (!node || !ref || !child) {
        LOG_MSG("add_child16: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    // Validate node type
    if (node->base.type != NODE16) {
        LOG_MSG("add_child16: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    // Check for duplicate key
    for (USHORT i = 0; i < node->base.num_of_child && i < 16; i++) {
        if (node->keys[i] == c) {
            LOG_MSG("add_child16: Duplicate key %d", c);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    // If node has capacity, add child directly
    if (node->base.num_of_child < 16) {
        // Find insertion position to maintain sorted order
        USHORT idx = 0;
        while (idx < node->base.num_of_child && node->keys[idx] < c) {
            idx++;
        }

        if (idx > 16 || node->base.num_of_child >= 16) {
            LOG_MSG("add_child16: Invalid insertion index");
            return STATUS_INTERNAL_ERROR;
        }

        // Shift existing elements to make room (overlapping ranges!)
        if (idx < node->base.num_of_child) {
            SIZE_T count_to_move = (SIZE_T)(node->base.num_of_child - idx);

            if (idx + count_to_move >= 16) {
                LOG_MSG("add_child16: shift would overflow array (idx=%u, move=%Iu)", idx, count_to_move);
                return STATUS_INTERNAL_ERROR;
            }

            if (count_to_move > 0) {
                RtlMoveMemory(&node->keys[idx + 1], &node->keys[idx], count_to_move * sizeof(UCHAR));
                RtlMoveMemory(&node->children[idx + 1], &node->children[idx], count_to_move * sizeof(PVOID));
            }
        }

        // After insertion
        node->keys[idx] = c;
        node->children[idx] = (ART_NODE*)child;
        node->base.num_of_child++;

        return STATUS_SUCCESS;
    }
    else {
        // Node is full, expand to NODE48
        ART_NODE48* new_node = (ART_NODE48*)art_create_node(NODE48);
        if (!new_node) {
            LOG_MSG("add_child16: Failed to create NODE48");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = STATUS_SUCCESS;

        // Initialize child_index array (all zeros means empty)
        RtlZeroMemory(new_node->child_index, sizeof(new_node->child_index));

        // Copy header information first
        status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child16: Failed to copy header");
            goto cleanup_and_exit;
        }

        // Copy existing children and build index map
        RtlCopyMemory(new_node->children, node->children,
            sizeof(PVOID) * node->base.num_of_child);

        for (USHORT i = 0; i < node->base.num_of_child && i < 16; i++) {
            new_node->child_index[node->keys[i]] = (UCHAR)(i + 1);  // +1 because 0 means empty
        }

        // Update reference before adding new child
        ART_NODE* old_node = (ART_NODE*)node;
        *ref = (ART_NODE*)new_node;

        // Add the new child
        status = add_child48(new_node, ref, c, child);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child16: Failed to add child to new NODE48");
            *ref = old_node; // Rollback
            goto cleanup_and_exit;
        }

        // Free old node
        free_node(&old_node);
        return STATUS_SUCCESS;

    cleanup_and_exit:
        if (new_node) {
            free_node((ART_NODE**)&new_node);
        }
        return status;
    }
}

STATIC NTSTATUS add_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child) {
    if (!node || !ref || !child) {
        LOG_MSG("add_child4: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (node->base.type != NODE4) {
        LOG_MSG("add_child4: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    // Check for duplicate key
    for (USHORT i = 0; i < node->base.num_of_child && i < 4; i++) {
        if (node->keys[i] == c) {
            LOG_MSG("add_child4: Duplicate key %d", c);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    // If node has capacity, add child directly
    if (node->base.num_of_child < 4) {
        // Find insertion position to maintain sorted order
        USHORT idx = 0;
        while (idx < node->base.num_of_child && node->keys[idx] < c) {
            idx++;
        }

        if (idx >= 4 || node->base.num_of_child >= 4) {
            LOG_MSG("add_child4: Invalid insertion index %d", idx);
            return STATUS_INTERNAL_ERROR;
        }

        // Shift existing elements to make room (overlapping ranges!)
        if (idx < node->base.num_of_child) {
            SIZE_T count_to_move = (SIZE_T)(node->base.num_of_child - idx);

            if (idx + count_to_move >= 4) {
                LOG_MSG("add_child4: shift would overflow array (idx=%u, move=%Iu)", idx, count_to_move);
                return STATUS_INTERNAL_ERROR;
            }

            if (count_to_move > 0) {
                RtlMoveMemory(&node->keys[idx + 1], &node->keys[idx], count_to_move * sizeof(UCHAR));
                RtlMoveMemory(&node->children[idx + 1], &node->children[idx], count_to_move * sizeof(PVOID));
            }
        }

        // Insert new element
        node->keys[idx] = c;
        node->children[idx] = (ART_NODE*)child;
        node->base.num_of_child++;

        return STATUS_SUCCESS;

    }
    else {
        // Node is full, expand to NODE16
        ART_NODE16* new_node = (ART_NODE16*)art_create_node(NODE16);
        if (!new_node) {
            LOG_MSG("add_child4: Failed to create NODE16");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = STATUS_SUCCESS;

        // Copy header information first
        status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child4: Failed to copy header");
            goto cleanup_and_exit;
        }

        // Copy existing children and keys (maintain sorted order)
        RtlCopyMemory(new_node->children, node->children, sizeof(PVOID) * node->base.num_of_child);
        RtlCopyMemory(new_node->keys, node->keys, sizeof(UCHAR) * node->base.num_of_child);

        // Update reference atomically before adding new child
        ART_NODE* old_node = (ART_NODE*)node;
        *ref = (ART_NODE*)new_node;

        // Add the new child
        status = add_child16(new_node, ref, c, child);
        if (!NT_SUCCESS(status)) {
            LOG_MSG("add_child4: Failed to add child to new NODE16");
            *ref = old_node; // Rollback
            goto cleanup_and_exit;
        }

        // Free old node
        free_node(&old_node);
        return STATUS_SUCCESS;

    cleanup_and_exit:
        if (new_node) {
            free_node((ART_NODE**)&new_node);
        }
        return status;
    }
}

STATIC NTSTATUS add_child(_Inout_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child) {
    if (!node || !ref || !child) {
        LOG_MSG("add_child: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    switch (node->type) {
    case NODE4:
        return add_child4((ART_NODE4*)node, ref, c, child);

    case NODE16:
        return add_child16((ART_NODE16*)node, ref, c, child);

    case NODE48:
        return add_child48((ART_NODE48*)node, ref, c, child);

    case NODE256:
        return add_child256((ART_NODE256*)node, ref, c, child);

    default:
        LOG_MSG("add_child: Invalid node type %d", node->type);
        return STATUS_INVALID_PARAMETER;
    }
}

STATIC NTSTATUS recursive_insert(_Inout_opt_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ CONST PUCHAR key, _In_ USHORT key_length, _In_ ULONG value, _In_ USHORT depth, _Out_ PBOOLEAN old, _In_ BOOLEAN replace, _Out_ PULONG old_value) {
    NTSTATUS status = STATUS_SUCCESS;

    // Basic argument validation
    if (!ref || !key || !old || !old_value) {
        LOG_MSG("recursive_insert: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (depth > key_length) {
        LOG_MSG("recursive_insert: Depth %u exceeds key length %u", depth, key_length);
        return STATUS_INVALID_PARAMETER;
    }

    *old = FALSE;
    *old_value = POLICY_NONE;

    // Case 1: We reached a NULL slot, attach a fresh leaf here.
    if (!node) {
        ART_LEAF* new_leaf = make_leaf(key, key_length, value);
        if (!new_leaf) {
            LOG_MSG("recursive_insert: Failed to create leaf");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // Publish the new leaf into the parent's child pointer
        *ref = (ART_NODE*)SET_LEAF(new_leaf);
        return STATUS_SUCCESS;
    }

    // Case 2: We hit a leaf. Either update it (if same key) or split it.
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            LOG_MSG("recursive_insert: Invalid leaf node");
            return STATUS_DATA_ERROR;
        }

        // Key already exists , report 'old', update if requested, and return
        if (leaf_matches(leaf, key, key_length)) {
            *old = TRUE;
            *old_value = leaf->value;
            if (replace) {
                leaf->value = value;
            }
            return STATUS_SUCCESS;
        }

        // Different key but we encountered a leaf, must split into an internal node
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
        if (!new_node) {
            LOG_MSG("recursive_insert: Failed to create NODE4 for split");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Create leaf for the incoming key
        ART_LEAF* new_leaf = make_leaf(key, key_length, value);
        if (!new_leaf) {
            free_node((ART_NODE**)&new_node);
            LOG_MSG("recursive_insert: Failed to create new leaf for split");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Find the longest common prefix from current depth
        USHORT lcp = longest_common_prefix(leaf, new_leaf, depth);
        // Safety: lcp cannot exceed the shorter remaining key length
        USHORT max_remaining = min(leaf->key_length > depth ? leaf->key_length - depth : 0,
            new_leaf->key_length > depth ? new_leaf->key_length - depth : 0);
        if (lcp > max_remaining) {
            free_leaf(&new_leaf);
            free_node((ART_NODE**)&new_node);
            LOG_MSG("recursive_insert: Invalid prefix calculation (lcp overflow)");
            return STATUS_DATA_ERROR;
        }

        // Store common prefix bytes into the new internal node
        new_node->base.prefix_length = lcp;
        if (lcp > 0) {
            SIZE_T copy_size = min(MAX_PREFIX_LENGTH, lcp);
            // Verify source bounds before copying
            if (depth + copy_size > key_length) {
                copy_size = key_length - depth;
            }
            if (copy_size > 0) {
                RtlCopyMemory(new_node->base.prefix, key + depth, copy_size);
            }
        }

        // Determine branch bytes with end-of-key handling.
        USHORT split_depth = depth + lcp;

        // Use 0x00 terminator edge when a key ends at split point (prefix-case).
        UCHAR old_edge = (split_depth < leaf->key_length) ? leaf->key[split_depth] : 0;
        UCHAR new_edge = (split_depth < new_leaf->key_length) ? new_leaf->key[split_depth] : 0;

        // Check for edge byte collision before proceeding
        if (old_edge == new_edge) {
            free_leaf(&new_leaf);
            free_node((ART_NODE**)&new_node);
            LOG_MSG("recursive_insert: Edge byte collision during split");
            return STATUS_DATA_ERROR;
        }

        // Build the new internal node *locally* first (publish-late)
        ART_NODE* tmp_ref = (ART_NODE*)new_node;

        // Add the old leaf under its diverging/terminator byte
        status = add_child4(new_node, &tmp_ref, old_edge, SET_LEAF(leaf));
        if (!NT_SUCCESS(status)) {
            free_leaf(&new_leaf);
            free_node((ART_NODE**)&new_node);
            LOG_MSG("recursive_insert: Failed to add existing leaf to split NODE4");
            return status;
        }

        // Update new_node reference if it was changed during expansion
        new_node = (ART_NODE4*)tmp_ref;

        // Add the new leaf under the other diverging/terminator byte
        status = add_child4(new_node, &tmp_ref, new_edge, SET_LEAF(new_leaf));
        if (!NT_SUCCESS(status)) {
            // Need to clean up - tmp_ref contains the node with old leaf already added
            free_node(&tmp_ref);
            free_leaf(&new_leaf);
            LOG_MSG("recursive_insert: Failed to add new leaf to split NODE4");
            return status;
        }

        // All good, publish the new internal node to the parent pointer
        *ref = tmp_ref;
        return STATUS_SUCCESS;
    }

    // Case 3: We're at an internal node. Handle its compressed prefix.
    // If the prefix fully matches, descend. If not, split the prefix.
    if (node->prefix_length > 0) {
        // Compare the stored (possibly truncated) prefix with key at 'depth'
        USHORT prefix_diff = prefix_mismatch(node, key, key_length, depth);

        // If the entire node's prefix matches, just skip over it and continue
        if (prefix_diff >= node->prefix_length) {
            // Advance depth by the node's full prefix length
            if ((USHORT)(depth + node->prefix_length) < depth) {
                LOG_MSG("recursive_insert: Depth overflow while skipping prefix");
                return STATUS_INTEGER_OVERFLOW;
            }
            depth += node->prefix_length;

            // If the key ends exactly here, attach/update a 0x00 terminator leaf.
            if (depth == key_length) {
                ART_NODE** term = find_child(node, 0);
                if (term && *term) {
                    if (!IS_LEAF(*term)) {
                        LOG_MSG("recursive_insert: Terminator edge not a leaf");
                        return STATUS_DATA_ERROR;
                    }
                    ART_LEAF* tleaf = LEAF_RAW(*term);
                    if (!tleaf) {
                        LOG_MSG("recursive_insert: Invalid terminator leaf");
                        return STATUS_DATA_ERROR;
                    }
                    *old = TRUE;
                    *old_value = tleaf->value;
                    if (replace) {
                        tleaf->value = value;
                    }
                    return STATUS_SUCCESS;
                }
                else {
                    ART_LEAF* tleaf = make_leaf(key, key_length, value);
                    if (!tleaf) {
                        LOG_MSG("recursive_insert: Failed to create terminator leaf");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    NTSTATUS st2 = add_child(node, ref, 0, SET_LEAF(tleaf));
                    if (!NT_SUCCESS(st2)) {
                        free_leaf(&tleaf);
                        LOG_MSG("recursive_insert: Failed to add terminator child");
                        return st2;
                    }
                    return STATUS_SUCCESS;
                }
            }
            // then continue to RECURSE_SEARCH below
        }
        else {
            // Prefix mismatch: we must split this internal node's prefix at 'prefix_diff'
            ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
            if (!new_node) {
                LOG_MSG("recursive_insert: Failed to create NODE4 for prefix split");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // The new parent node will hold the matched part of the prefix
            new_node->base.prefix_length = prefix_diff;
            if (prefix_diff > 0) {
                SIZE_T copy_size = min(MAX_PREFIX_LENGTH, prefix_diff);
                RtlCopyMemory(new_node->base.prefix, node->prefix, copy_size);
            }

            // Determine which edge byte leads to the *old* node (the first mismatching byte)
            UCHAR old_key_byte;
            if (node->prefix_length <= MAX_PREFIX_LENGTH) {
                // The mismatching byte is within the stored prefix
                if (prefix_diff >= node->prefix_length) {
                    free_node((ART_NODE**)&new_node);
                    LOG_MSG("recursive_insert: Prefix diff exceeds stored prefix");
                    return STATUS_DATA_ERROR;
                }
                old_key_byte = node->prefix[prefix_diff];
            }
            else {
                // For extended prefixes, fetch the actual byte from a representative leaf
                ART_LEAF* representative_leaf = minimum(node);
                if (!representative_leaf || depth + prefix_diff >= representative_leaf->key_length) {
                    free_node((ART_NODE**)&new_node);
                    LOG_MSG("recursive_insert: Cannot determine branch byte from leaf");
                    return STATUS_DATA_ERROR;
                }
                old_key_byte = representative_leaf->key[depth + prefix_diff];
            }

            // Shorten the *old* node's prefix (remove the matched part + the branch byte)
            USHORT new_prefix_length = 0;
            if (node->prefix_length > prefix_diff + 1) { // Prevent underflow
                new_prefix_length = node->prefix_length - (prefix_diff + 1);
            }

            if (new_prefix_length > 0) {
                if (node->prefix_length <= MAX_PREFIX_LENGTH) {
                    // Check bounds before memory move
                    if (prefix_diff + 1 < node->prefix_length) {
                        RtlMoveMemory(node->prefix,
                            &node->prefix[prefix_diff + 1],
                            min(MAX_PREFIX_LENGTH, new_prefix_length));
                    }
                }
                else {
                    ART_LEAF* representative_leaf = minimum(node);
                    if (representative_leaf && depth + prefix_diff + 1 < representative_leaf->key_length) {
                        SIZE_T copy_size = min(MAX_PREFIX_LENGTH, new_prefix_length);
                        // Ensure we don't read beyond the key length
                        if (depth + prefix_diff + 1 + copy_size <= representative_leaf->key_length) {
                            RtlCopyMemory(node->prefix,
                                &representative_leaf->key[depth + prefix_diff + 1],
                                copy_size);
                        }
                    }
                }
            }
            node->prefix_length = new_prefix_length;

            // Build new_node *locally* before publishing it
            ART_NODE* tmp_ref = (ART_NODE*)new_node;

            // Attach the old node under the edge byte taken from its (shortened) prefix
            status = add_child4(new_node, &tmp_ref, old_key_byte, node);
            if (!NT_SUCCESS(status)) {
                free_node((ART_NODE**)&new_node);
                LOG_MSG("recursive_insert: Failed to add old node to split NODE4");
                return status;
            }

            // Update new_node reference after potential expansion
            new_node = (ART_NODE4*)tmp_ref;

            // Create the leaf for the incoming key and attach it under its branch byte
            ART_LEAF* new_leaf = make_leaf(key, key_length, value);
            if (!new_leaf) {
                free_node(&tmp_ref); // Use tmp_ref which might have changed
                LOG_MSG("recursive_insert: Failed to create leaf for prefix split");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // If the new key ends at the split point, use a terminator edge (0x00)
            UCHAR new_edge = (depth + prefix_diff < key_length) ? key[depth + prefix_diff] : 0;

            // Check for edge collision
            if (old_key_byte == new_edge) {
                free_leaf(&new_leaf);
                free_node(&tmp_ref); // Use tmp_ref which might have changed
                LOG_MSG("recursive_insert: Edge collision during prefix split");
                return STATUS_DATA_ERROR;
            }

            status = add_child4(new_node, &tmp_ref, new_edge, SET_LEAF(new_leaf));
            if (!NT_SUCCESS(status)) {
                free_leaf(&new_leaf);
                free_node(&tmp_ref); // Use tmp_ref which might have changed
                LOG_MSG("recursive_insert: Failed to add new leaf after prefix split");
                return status;
            }

            // All done , now publish the split parent
            *ref = tmp_ref;
            return STATUS_SUCCESS;
        }
    }

    // RECURSE_SEARCH: Find the next child by key[depth]. If it exists, descend;
    // otherwise create a new leaf and attach it as a child.

    // *** FIX: handle exact end-of-key here by using the 0x00 terminator edge ***
    if (depth == key_length) {
        ART_NODE** term = find_child(node, 0);
        if (term && *term) {
            if (!IS_LEAF(*term)) {
                LOG_MSG("recursive_insert: Terminator edge not a leaf (no-prefix path)");
                return STATUS_DATA_ERROR;
            }
            ART_LEAF* tleaf = LEAF_RAW(*term);
            if (!tleaf) {
                LOG_MSG("recursive_insert: Invalid terminator leaf (no-prefix path)");
                return STATUS_DATA_ERROR;
            }
            *old = TRUE;
            *old_value = tleaf->value;
            if (replace) {
                tleaf->value = value;
            }
            return STATUS_SUCCESS;
        }
        else {
            ART_LEAF* tleaf = make_leaf(key, key_length, value);
            if (!tleaf) {
                LOG_MSG("recursive_insert: Failed to create terminator leaf (no-prefix path)");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            NTSTATUS st2 = add_child(node, ref, 0, SET_LEAF(tleaf));
            if (!NT_SUCCESS(st2)) {
                free_leaf(&tleaf);
                LOG_MSG("recursive_insert: Failed to add terminator child (no-prefix path)");
                return st2;
            }
            return STATUS_SUCCESS;
        }
    }
    // (depth > key_length) already rejected at top.

    // Try to find existing child for the next byte
    ART_NODE** child = find_child(node, key[depth]);
    if (child && *child) { // Validate both child pointer and its target
        // Recurse into the child (pass 'child' as the new 'ref' so updates publish correctly)
        return recursive_insert(*child, child, key, key_length, value,
            depth + 1, old, replace, old_value);
    }

    // No child for this byte , add a fresh leaf as a new child edge
    ART_LEAF* new_leaf = make_leaf(key, key_length, value);
    if (!new_leaf) {
        LOG_MSG("recursive_insert: Failed to create leaf for new child");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = add_child(node, ref, key[depth], SET_LEAF(new_leaf));
    if (!NT_SUCCESS(status)) {
        free_leaf(&new_leaf);
        LOG_MSG("recursive_insert: Failed to add new child at depth %u", depth);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS art_insert(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key, _In_ ULONG value, _Out_opt_ PULONG old_value) {
    // Input validation
    if (!tree || !unicode_key) {
        LOG_MSG("art_insert: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (unicode_key->Length == 0) {
        LOG_MSG("art_insert: Empty key not allowed");
        return STATUS_INVALID_PARAMETER;
    }

    // Convert Unicode to UTF-8
    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        LOG_MSG("art_insert: Failed to convert Unicode key");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("art_insert: Key length %u exceeds MAX_KEY_LENGTH %u", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return STATUS_INVALID_PARAMETER;
    }

    BOOLEAN is_existing = FALSE;
    ULONG old_val = POLICY_NONE;

    // Perform the recursive insertion
    NTSTATUS status = recursive_insert(
        tree->root,
        &tree->root,
        key,
        key_length,
        value,
        0,
        &is_existing,
        TRUE, // replace existing values if key matches
        &old_val
    );

    // If insert succeeded and this is a NEW key (not replacing an existing one)
    if (NT_SUCCESS(status) && !is_existing) {
        // Check for tree size overflow BEFORE incrementing size
        if (tree->size == MAXULONG) {
            // --- ROLLBACK LOGIC START ---
            // 1) Remove the just-inserted key to restore previous state
            ART_LEAF* removed = recursive_delete(tree->root, &tree->root, key, key_length, 0);
            if (removed) {
                // 2) Free the removed leaf to prevent memory leak
                free_leaf(&removed);
            }
            // 3) Free the temporary UTF-8 key buffer
            destroy_utf8_key(key);
            // 4) Return overflow error without leaving the inserted key in the tree
            LOG_MSG("art_insert: Tree size overflow (rolled back)");
            return STATUS_INTEGER_OVERFLOW;
            // --- ROLLBACK LOGIC END ---
        }

        // No overflow, safe to increment the size
        tree->size++;
    }

    // Output the old value if the caller provided a pointer
    if (old_value) {
        *old_value = old_val;
    }

    destroy_utf8_key(key);

    return status;
}

NTSTATUS art_insert_no_replace(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key, _In_ ULONG value, _Out_opt_ PULONG existing_value) {
    // Guard: required pointers
    if (!tree || !unicode_key) {
        LOG_MSG("art_insert_no_replace: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    // Guard: empty key
    if (unicode_key->Length == 0) {
        LOG_MSG("art_insert_no_replace: Empty key not allowed");
        return STATUS_INVALID_PARAMETER;
    }

    // Convert to UTF-8 (lowercased by unicode_to_utf8)
    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        LOG_MSG("art_insert_no_replace: Failed to convert Unicode key");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Guard: enforce maximum key length (in bytes)
    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("art_insert_no_replace: Key length %u exceeds MAX_KEY_LENGTH %u", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return STATUS_INVALID_PARAMETER;
    }

    BOOLEAN is_existing = FALSE;
    ULONG old_val = POLICY_NONE;

    NTSTATUS status = recursive_insert(tree->root, &tree->root, key, key_length, value, 0, &is_existing, FALSE, &old_val);

    // Existing key, report collision (do not replace)
    if (NT_SUCCESS(status) && is_existing) {
        if (existing_value) {
            *existing_value = old_val;
        }
        destroy_utf8_key(key);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    // New key: size++ with overflow protection. On overflow, rollback the structural insert.
    if (NT_SUCCESS(status) && !is_existing) {
        if (tree->size == MAXULONG) {
            LOG_MSG("art_insert_no_replace: Tree size overflow, rolling back insertion");
            // Roll back by removing the just-inserted key.
            ART_LEAF* removed = recursive_delete(tree->root, &tree->root, key, key_length, 0);
            if (removed) {
                free_leaf(&removed); // free removed leaf to avoid leaks
            }
            destroy_utf8_key(key);
            return STATUS_INTEGER_OVERFLOW;
        }
        tree->size++;
    }

    // Return the previous value if requested (POLICY_NONE for new keys)
    if (existing_value) {
        *existing_value = old_val;
    }

    destroy_utf8_key(key);
    return status;
}

/** REMOVE Functions*/

// Removes a single child byte 'c' from a NODE256.
// If this removal leaves the node empty, free it and set *ref = NULL.
// Otherwise, if the node underflows (<= 37 children), shrink to NODE48.
STATIC NTSTATUS remove_child256(_In_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c) {
    if (!node || !ref) {
        DbgPrint("[ART] remove_child256: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Backup for potential rollback during shrink.
    ART_NODE* backup = node->children[c];
    if (!backup) {
        DbgPrint("[ART] remove_child256: Child at index %u does not exist\n", c);
        return STATUS_NOT_FOUND;
    }

    // Remove the edge.
    node->children[c] = NULL;
    if (node->base.num_of_child == 0) {
        // Defensive: shouldn't happen, but avoid underflow.
        DbgPrint("[ART] remove_child256: num_of_child already 0 before decrement\n");
        return STATUS_DATA_ERROR;
    }
    node->base.num_of_child--;

    // If we are now empty, remove this internal node entirely.
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        free_node((ART_NODE**)&node);
        return STATUS_SUCCESS;
    }

    // Underflow: shrink 256 -> 48 when <= 37 children remain.
    if (node->base.num_of_child <= 37) {
        ART_NODE48* new_node = (ART_NODE48*)art_create_node(NODE48);
        if (!new_node) {
            // Roll back the edge removal.
            node->children[c] = backup;
            node->base.num_of_child++;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            free_node((ART_NODE**)&new_node);
            node->children[c] = backup;
            node->base.num_of_child++;
            return status;
        }

        // Repack survivors into NODE48
        USHORT pos = 0;
        for (USHORT i = 0; i < 256; i++) {
            ART_NODE* child = node->children[i];
            if (!child) continue;
            if (pos >= 48) {
                // Defensive: should be impossible with correct threshold.
                free_node((ART_NODE**)&new_node);
                node->children[c] = backup;
                node->base.num_of_child++;
                return STATUS_DATA_ERROR;
            }
            new_node->children[pos] = child;
            new_node->child_index[i] = (UCHAR)(pos + 1);
            pos++;
        }
        new_node->base.num_of_child = pos;

        // Publish and free old node.
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE**)&node);
    }

    return STATUS_SUCCESS;
}

// Removes key byte 'c' from a NODE48.
// If this removal leaves the node empty, free it and set *ref = NULL.
// Otherwise, if the node underflows (<= 12), shrink to NODE16.
STATIC NTSTATUS remove_child48(_In_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c) {
    if (!node || !ref) {
        DbgPrint("[ART] remove_child48: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    int pos = node->child_index[c];
    if (pos == 0 || pos > 48) {
        DbgPrint("[ART] remove_child48: Invalid child index %d for key %u\n", pos, c);
        return STATUS_NOT_FOUND;
    }
    int actual_pos = pos - 1;
    if (actual_pos < 0 || actual_pos >= 48) {
        DbgPrint("[ART] remove_child48: Actual position %d out of bounds\n", actual_pos);
        return STATUS_INVALID_PARAMETER;
    }
    ART_NODE* backup_child = node->children[actual_pos];
    if (!backup_child) {
        DbgPrint("[ART] remove_child48: Child at position %d is NULL\n", actual_pos);
        return STATUS_NOT_FOUND;
    }

    // Remove mapping and edge.
    node->child_index[c] = 0;
    node->children[actual_pos] = NULL;
    if (node->base.num_of_child == 0) {
        // Defensive: avoid underflow.
        DbgPrint("[ART] remove_child48: num_of_child already 0 before decrement\n");
        return STATUS_DATA_ERROR;
    }
    node->base.num_of_child--;

    // If empty now, drop this internal node entirely.
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        free_node((ART_NODE**)&node);
        return STATUS_SUCCESS;
    }

    // Underflow: shrink 48 -> 16 when <= 12 children remain.
    if (node->base.num_of_child <= 12) {
        ART_NODE16* new_node = (ART_NODE16*)art_create_node(NODE16);
        if (!new_node) {
            // Full rollback
            node->child_index[c] = (UCHAR)pos;
            node->children[actual_pos] = backup_child;
            node->base.num_of_child++;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            free_node((ART_NODE**)&new_node);
            node->child_index[c] = (UCHAR)pos;
            node->children[actual_pos] = backup_child;
            node->base.num_of_child++;
            return status;
        }

        USHORT out = 0;
        for (USHORT i = 0; i < 256; i++) {
            int map = node->child_index[i];
            if (map <= 0) continue;
            if (map > 48 || out >= 16) {
                // Defensive: should not happen with correct threshold.
                free_node((ART_NODE**)&new_node);
                node->child_index[c] = (UCHAR)pos;
                node->children[actual_pos] = backup_child;
                node->base.num_of_child++;
                return STATUS_DATA_ERROR;
            }
            ART_NODE* child_ptr = node->children[map - 1];
            if (!child_ptr) continue; // skip inconsistent holes
            new_node->keys[out] = (UCHAR)i;
            new_node->children[out] = child_ptr;
            out++;
        }
        new_node->base.num_of_child = out;

        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE**)&node);
    }

    return STATUS_SUCCESS;
}

// Removes the child pointed to by 'leaf' from a NODE16.
// Atomic shrink path:
//   If removal would underflow (current count == 4), build a fresh NODE4
//   *without* mutating the original node. Publish only on full success.
// Non-shrink path:
//   Do the in-place left shift (uses RtlMoveMemory for overlapping ranges).
STATIC NTSTATUS remove_child16(_In_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ ART_NODE** leaf) {
    if (!node || !ref || !leaf) {
        DbgPrint("[ART] remove_child16: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Compute the index via pointer arithmetic (leaf must point into children[])
    INT64 pos64 = leaf - node->children;
    if (pos64 < 0 || pos64 >= 16) {
        DbgPrint("[ART] remove_child16: Invalid position %lld\n", pos64);
        return STATUS_INVALID_PARAMETER;
    }
    USHORT pos = (USHORT)pos64;

    if (pos >= node->base.num_of_child) {
        DbgPrint("[ART] remove_child16: Position %u exceeds child count %u\n", pos, node->base.num_of_child);
        return STATUS_INVALID_PARAMETER;
    }
    if (!node->children[pos]) {
        DbgPrint("[ART] remove_child16: Child at position %u is NULL\n", pos);
        return STATUS_NOT_FOUND;
    }

    // ===== Atomic shrink path =====
    // If after removal the count would be <=3, that means current count must be 4.
    if (node->base.num_of_child == 4) {
        // Build a new NODE4 from the 4 entries, skipping index 'pos'.
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
        if (!new_node) {
            DbgPrint("[ART] remove_child16: Failed to create NODE4\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            free_node((ART_NODE**)&new_node);
            return status;
        }

        // Copy the 3 live entries in ascending order, skipping 'pos'.
        USHORT out = 0;
        for (USHORT i = 0; i < 4; i++) {
            if (i == pos) continue;
            new_node->keys[out] = node->keys[i];
            new_node->children[out] = node->children[i];
            out++;
        }
        new_node->base.num_of_child = out; // must be 3

        // Publish only after the new node is fully built
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE**)&node);
        return STATUS_SUCCESS;
    }

    // ===== Non-shrink path: in-place removal and shift left =====
    ULONG remaining = node->base.num_of_child - 1 - (ULONG)pos;
    if (remaining > 0) {
        // Overlapping ranges , use RtlMoveMemory
        RtlMoveMemory(&node->keys[pos], &node->keys[pos + 1], remaining * sizeof(UCHAR));
        RtlMoveMemory(&node->children[pos], &node->children[pos + 1], remaining * sizeof(VOID*));
    }

    // Clear the duplicate tail slot for hygiene
    USHORT last = node->base.num_of_child - 1;
    node->keys[last] = 0;
    node->children[last] = NULL;

    node->base.num_of_child--;

    // No shrink (we already handled the only underflowing case above)
    return STATUS_SUCCESS;
}

// Removes the child pointed to by 'leaf' from a NODE4.
// - Uses RtlMoveMemory because ranges overlap when shifting left.
// - If exactly one child remains, collapses this node by merging our prefix + edge byte
//   into the child and bypassing this node.
// - If no child remains, frees this node and sets *ref = NULL.
// Note: prefix_length is kept consistent with the bytes we actually store here
// (clamped at MAX_PREFIX_LENGTH), matching the rest of this codebase.
STATIC NTSTATUS remove_child4(_In_ ART_NODE4* node, _Inout_ ART_NODE** ref, _In_ ART_NODE** leaf) {
    if (!node || !ref || !leaf) {
        DbgPrint("[ART] remove_child4: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Locate the exact slot by pointer match (address equality with children[i])
    INT64 pos = -1;
    for (USHORT i = 0; i < node->base.num_of_child && i < 4; i++) {
        if (&node->children[i] == leaf) { pos = i; break; }
    }
    if (pos < 0 || pos >= 4) {
        DbgPrint("[ART] remove_child4: Invalid leaf pointer\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (!node->children[pos]) {
        DbgPrint("[ART] remove_child4: Child at position %lld is NULL\n", pos);
        return STATUS_NOT_FOUND;
    }

    // Shift left to fill the gap (overlapping ranges!)
    ULONG remaining = node->base.num_of_child - 1 - (ULONG)pos;
    if (remaining > 0) {
        RtlMoveMemory(&node->keys[pos], &node->keys[pos + 1], remaining * sizeof(UCHAR));
        RtlMoveMemory(&node->children[pos], &node->children[pos + 1], remaining * sizeof(VOID*));
    }

    // Clear last slot for cleanliness
    if (node->base.num_of_child > 0) {
        USHORT last = node->base.num_of_child - 1;
        node->keys[last] = 0;
        node->children[last] = NULL;
    }

    node->base.num_of_child--;

    // If no child remains, free this node and null out the reference.
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        free_node((ART_NODE**)&node);
        return STATUS_SUCCESS;
    }

    // Collapse optimization: if only 1 child remains, merge prefixes and bypass this node
    if (node->base.num_of_child == 1) {
        ART_NODE* child = node->children[0];
        if (!child) {
            DbgPrint("[ART] remove_child4: Remaining child is NULL\n");
            return STATUS_DATA_ERROR;
        }

        // Merge our prefix + edge key into child's prefix if child is internal
        if (!IS_LEAF(child)) {
            ART_NODE* child_node = (ART_NODE*)child;
            USHORT total_prefix_len = 0;                   // number of bytes we will actually store
            UCHAR  new_prefix[MAX_PREFIX_LENGTH] = { 0 };

            // 1) Copy parent prefix (up to MAX_PREFIX_LENGTH)
            if (node->base.prefix_length > 0) {
                USHORT copy_len = min(node->base.prefix_length, MAX_PREFIX_LENGTH);
                RtlCopyMemory(new_prefix, node->base.prefix, copy_len);
                total_prefix_len += copy_len;
            }

            // 2) Append the only remaining edge byte
            if (total_prefix_len < MAX_PREFIX_LENGTH) {
                new_prefix[total_prefix_len++] = node->keys[0];
            }

            // 3) Append child's existing prefix (as much as will fit)
            if (child_node->prefix_length > 0 && total_prefix_len < MAX_PREFIX_LENGTH) {
                USHORT space_left = (USHORT)(MAX_PREFIX_LENGTH - total_prefix_len);
                USHORT copy_len = min(child_node->prefix_length, space_left);
                if (copy_len > 0) {
#pragma warning(push)
#pragma warning(disable : 6385)
                    RtlCopyMemory(new_prefix + total_prefix_len, child_node->prefix, copy_len);
#pragma warning(pop)
                    total_prefix_len = (USHORT)(total_prefix_len + copy_len);
                }
            }

            // Commit merged prefix (clamped to MAX_PREFIX_LENGTH)
            if (total_prefix_len > 0) {
                RtlCopyMemory(child_node->prefix, new_prefix, total_prefix_len);
            }
            child_node->prefix_length = total_prefix_len;
        }

        // Bypass this node
        *ref = child;
        free_node((ART_NODE**)&node);
    }

    return STATUS_SUCCESS;
}

STATIC NTSTATUS remove_child(_In_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_opt_ ART_NODE** leaf) {
    NTSTATUS status = STATUS_SUCCESS;

    if (!node || !ref) {
        DbgPrint("[ART] remove_child: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    switch (node->type) {
    case NODE4:
        if (!leaf) {
            DbgPrint("[ART] remove_child: NODE4 requires leaf parameter\n");
            return STATUS_INVALID_PARAMETER;
        }
        status = remove_child4((ART_NODE4*)node, ref, leaf);
        break;

    case NODE16:
        if (!leaf) {
            DbgPrint("[ART] remove_child: NODE16 requires leaf parameter\n");
            return STATUS_INVALID_PARAMETER;
        }
        status = remove_child16((ART_NODE16*)node, ref, leaf);
        break;

    case NODE48:
        status = remove_child48((ART_NODE48*)node, ref, c);
        break;

    case NODE256:
        status = remove_child256((ART_NODE256*)node, ref, c);
        break;

    default:
        DbgPrint("[ART] remove_child: Unexpected node type %d\n", node->type);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

// Delete a single key (internal routine). Handles long prefixes safely by
// validating bytes beyond MAX_PREFIX_LENGTH using a representative leaf.
STATIC ART_LEAF* recursive_delete_internal(_In_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth, _In_ USHORT recursion_depth) {
    if (recursion_depth > MAX_RECURSION_DEPTH) {
        DbgPrint("[ART] Maximum recursion depth exceeded\n");
        return NULL;
    }

    if (!node || !ref || !key) {
        return NULL;
    }

    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            DbgPrint("[ART] Invalid leaf node detected\n");
            return NULL;
        }

        if (leaf_matches(leaf, key, key_length)) {
            *ref = NULL;  // Detach the leaf; caller will free it
            return leaf;
        }

        return NULL;
    }

    if (node->prefix_length > 0) {
        USHORT match_len = check_prefix(node, key, key_length, depth);
        USHORT expected = (USHORT)min(MAX_PREFIX_LENGTH, node->prefix_length);

        if (match_len != expected) {
            return NULL;
        }

        // For nodes whose prefix is longer than MAX_PREFIX_LENGTH, validate remaining bytes
        if (node->prefix_length > MAX_PREFIX_LENGTH) {
            // Ensure key is long enough for full prefix and avoid overflow
            if ((USHORT)(depth + node->prefix_length) < depth || (depth + node->prefix_length) > key_length) {
                DbgPrint("[ART] Prefix exceeds key length in delete path\n");
                return NULL;
            }
            const ART_LEAF* rep = minimum(node);
            if (!rep) {
                DbgPrint("[ART] Could not fetch representative leaf for long-prefix compare\n");
                return NULL;
            }

            // Check if representative leaf key is valid for comparison
            if (!rep->key || rep->key_length < (depth + node->prefix_length)) {
                DbgPrint("[ART] Representative leaf key too short for comparison\n");
                return NULL;
            }

            USHORT rem = (USHORT)(node->prefix_length - MAX_PREFIX_LENGTH);
            for (USHORT i = 0; i < rem; ++i) {
                // Additional bounds check to prevent buffer overrun
                if ((depth + MAX_PREFIX_LENGTH + i) >= key_length ||
                    (depth + MAX_PREFIX_LENGTH + i) >= rep->key_length) {
                    DbgPrint("[ART] Bounds exceeded during extended prefix comparison\n");
                    return NULL;
                }
                if (rep->key[depth + MAX_PREFIX_LENGTH + i] != key[depth + MAX_PREFIX_LENGTH + i]) {
                    return NULL;
                }
            }
        }

        if ((USHORT)(depth + node->prefix_length) < depth) {
            DbgPrint("[ART] Depth overflow detected\n");
            return NULL;
        }

        depth += node->prefix_length;
    }

    // Handle terminator edge case when key ends exactly at current depth
    if (depth == key_length) {
        // Look for terminator child (key byte 0)
        ART_NODE** term_ref = find_child(node, 0);
        if (!term_ref || !*term_ref) {
            return NULL; // No terminator edge found
        }

        if (!IS_LEAF(*term_ref)) {
            DbgPrint("[ART] Terminator edge is not a leaf\n");
            return NULL;
        }

        ART_LEAF* term_leaf = LEAF_RAW(*term_ref);
        if (!term_leaf) {
            DbgPrint("[ART] Invalid terminator leaf detected\n");
            return NULL;
        }

        if (leaf_matches(term_leaf, key, key_length)) {
            NTSTATUS status = remove_child(node, ref, 0, term_ref);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[ART] Failed to remove terminator child, status: 0x%x\n", status);
                return NULL;
            }
            return term_leaf;
        }

        return NULL;
    }

    // Ensure we still have bytes to process
    if (depth >= key_length) {
        return NULL;
    }

    ART_NODE** child_ref = find_child(node, key[depth]);
    if (!child_ref || !*child_ref) {
        return NULL;
    }

    ART_NODE* child_node = *child_ref;

    // Leaf child case
    if (IS_LEAF(child_node)) {
        ART_LEAF* leaf = LEAF_RAW(child_node);
        if (!leaf) {
            DbgPrint("[ART] Invalid child leaf detected\n");
            return NULL;
        }

        if (leaf_matches(leaf, key, key_length)) {
            NTSTATUS status = remove_child(node, ref, key[depth], child_ref);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[ART] Failed to remove child, status: 0x%x\n", status);
                return NULL;
            }

            return leaf;
        }

        return NULL;
    }


    if (recursion_depth >= MAX_RECURSION_DEPTH) {
        DbgPrint("[ART] Recursion depth overflow\n");
        return NULL;
    }

    return recursive_delete_internal(child_node, child_ref, key, key_length, (USHORT)(depth + 1), (USHORT)(recursion_depth + 1));
}

STATIC ART_LEAF* recursive_delete(_In_opt_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth)
{
    if (!node || !ref || !key || key_length == 0) {
        return NULL;
    }
    // Top-level API: depth must be 0. (Internal recursion uses recursive_delete_internal.)
    if (depth != 0) {
        DbgPrint("[ART] recursive_delete: depth must be 0 for public entry\n");
        return NULL;
    }

    return recursive_delete_internal(node, ref, key, key_length, /*depth*/0, /*rec_depth*/0);
}

ULONG art_delete(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key)
{
    if (!tree || !unicode_key) {
        return POLICY_NONE;
    }
    if (tree->size == 0) {
        DbgPrint("[ART] Tree is empty\n");
        return POLICY_NONE;
    }

    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        DbgPrint("[ART] Failed to convert Unicode to UTF-8\n");
        return POLICY_NONE;
    }

    // Optional: early rejects for degenerate or absurdly long keys (keeps symmetry with insert)
    if (key_length == 0) {
        DbgPrint("[ART] Empty key after conversion\n");
        destroy_utf8_key(key);
        return POLICY_NONE;
    }
#ifdef MAX_KEY_LENGTH
    if (key_length > MAX_KEY_LENGTH) {
        DbgPrint("[ART] Key length %u exceeds MAX_KEY_LENGTH %u\n", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return POLICY_NONE;
    }
#endif

    ART_LEAF* deleted_leaf = recursive_delete(tree->root, &tree->root, key, key_length, 0);
    ULONG old_value = POLICY_NONE;

    if (deleted_leaf) {
        old_value = deleted_leaf->value;

        if (tree->size > 0) {
            tree->size--;
        }
        else {
            DbgPrint("[ART] Warning: Tree size was already 0\n");
        }

        free_leaf(&deleted_leaf);
        DbgPrint("[ART] Successfully deleted key, old value: %lu\n", old_value);
    }
    else {
        DbgPrint("[ART] Key not found for deletion\n");
    }

    destroy_utf8_key(key);
    return old_value;
}

// Deletes an entire subtree starting at 'node' and counts both leaves (keys)
// and total nodes freed. IMPORTANT: Only decrement tree->size by the number
// of leaves (do that in the wrapper below), not here.
STATIC NTSTATUS recursive_delete_all_internal(_Inout_ ART_TREE* tree, _In_opt_ ART_NODE* node, _Inout_ PULONG leaf_count, _Inout_ PULONG node_count, _In_ USHORT recursion_depth)
{
    if (recursion_depth > MAX_RECURSION_DEPTH) {
        DbgPrint("[ART] Maximum recursion depth exceeded in delete_all\n");
        return STATUS_STACK_OVERFLOW;
    }
    if (!node || !tree || !leaf_count || !node_count)
        return STATUS_SUCCESS; // no-op

    // Base case: leaf = actual key/value
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (leaf) {
            free_leaf(&leaf);
            (*leaf_count)++;
            (*node_count)++;   // leaf is also an object we freed
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS status = STATUS_SUCCESS;

    switch (node->type) {
    case NODE4: {
        ART_NODE4* n4 = (ART_NODE4*)node;
        USHORT cnt = min(n4->base.num_of_child, 4);
        for (USHORT i = 0; i < cnt; i++) {
            ART_NODE* ch = n4->children[i];
            if (ch) {
                status = recursive_delete_all_internal(tree, ch, leaf_count, node_count, (USHORT)(recursion_depth + 1));
                if (!NT_SUCCESS(status)) {
                    // prevent double-free in callers/cleanup paths
                    for (USHORT j = i; j < cnt; j++) {
                        n4->children[j] = NULL;
                    }
                    return status;
                }
                n4->children[i] = NULL;
            }
        }
    } break;

    case NODE16: {
        ART_NODE16* n16 = (ART_NODE16*)node;
        USHORT cnt = min(n16->base.num_of_child, 16);
        for (USHORT i = 0; i < cnt; i++) {
            ART_NODE* ch = n16->children[i];
            if (ch) {
                status = recursive_delete_all_internal(tree, ch, leaf_count, node_count, (USHORT)(recursion_depth + 1));
                if (!NT_SUCCESS(status)) {
                    for (USHORT j = i; j < cnt; j++) {
                        n16->children[j] = NULL;
                    }
                    return status;
                }
                n16->children[i] = NULL;
            }
        }
    } break;

    case NODE48: {
        ART_NODE48* n48 = (ART_NODE48*)node;
        for (USHORT i = 0; i < 256; i++) {
            UCHAR p = n48->child_index[i];
            if (p > 0 && p <= 48) {
                ART_NODE* ch = n48->children[p - 1];
                if (ch) {
                    status = recursive_delete_all_internal(tree, ch, leaf_count, node_count, (USHORT)(recursion_depth + 1));
                    if (!NT_SUCCESS(status)) {
                        n48->children[p - 1] = NULL;
                        n48->child_index[i] = 0;
                        return status;
                    }
                    n48->children[p - 1] = NULL;
                }
                n48->child_index[i] = 0;
            }
        }
    } break;

    case NODE256: {
        ART_NODE256* n256 = (ART_NODE256*)node;
        for (USHORT i = 0; i < 256; i++) {
            ART_NODE* ch = n256->children[i];
            if (ch) {
                status = recursive_delete_all_internal(tree, ch, leaf_count, node_count, (USHORT)(recursion_depth + 1));
                if (!NT_SUCCESS(status)) {
                    for (USHORT j = i; j < 256; j++) {
                        n256->children[j] = NULL;
                    }
                    return status;
                }
                n256->children[i] = NULL;
            }
        }
    } break;

    default:
        DbgPrint("[ART] Unexpected node type: %d\n", node->type);
        return STATUS_INVALID_PARAMETER;
    }

    // Free the current internal node after its children are freed
    free_node(&node);
    (*node_count)++;
    return STATUS_SUCCESS;
}

// --- Fallback: Iterative delete-all traversal to avoid deep recursion ---
// This function is used when recursive_delete_all_internal fails due to
// exceeding MAX_RECURSION_DEPTH (stack overflow risk) or other recursion limits.
// It performs a post-order traversal using an explicit stack allocated on the heap,
// freeing leaves and internal nodes without relying on the call stack.
typedef struct _DEL_FRAME {
    ART_NODE* node;     // current node being processed
    USHORT i;           // generic child index (for NODE4, NODE16, NODE256)
    USHORT map_i;       // index for scanning NODE48 child_index[256]
    BOOLEAN entered;    // whether we have already visited this node (pre/post traversal state)
} DEL_FRAME;
// Counts BOTH: leaf_count (keys) and node_count (all freed objects: leaves+internals)
static NTSTATUS force_delete_all_iterative(_Inout_ ULONG* leaf_count, _Inout_ ULONG* node_count, _Inout_ ART_NODE** proot)
{
    if (!proot || !*proot || !leaf_count || !node_count)
        return STATUS_SUCCESS;

    NTSTATUS status = STATUS_SUCCESS;

    SIZE_T cap = 64, sp = 0;
    DEL_FRAME* stk = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, cap * sizeof(DEL_FRAME), ART_TAG);
    if (!stk) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(stk, cap * sizeof(DEL_FRAME));

    ART_NODE* root = *proot;
    stk[sp++] = (DEL_FRAME){ .node = root, .i = 0, .map_i = 0, .entered = FALSE };

    while (sp > 0) {
        DEL_FRAME* fr = &stk[sp - 1];
        ART_NODE* n = fr->node;

        if (!n) { sp--; continue; }

        if (IS_LEAF(n)) {
            ART_LEAF* lf = LEAF_RAW(n);
            if (lf) {
                free_leaf(&lf);
                (*leaf_count)++;   // count key
                (*node_count)++;   // leaf is also a freed object
            }
            sp--;
            continue;
        }

        if (!fr->entered) {
            fr->entered = TRUE; fr->i = 0; fr->map_i = 0;
        }

        BOOLEAN pushed = FALSE;

        switch (n->type) {
        case NODE4: {
            ART_NODE4* p = (ART_NODE4*)n;
            USHORT max = min(p->base.num_of_child, 4);
            while (fr->i < max) {
                ART_NODE* ch = p->children[fr->i];
                p->children[fr->i] = NULL;
                fr->i++;
                if (ch) {
                    if (sp >= cap) {
                        SIZE_T ncap = cap * 2;
                        DEL_FRAME* tmp = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ncap * sizeof(DEL_FRAME), ART_TAG);
                        if (!tmp) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
                        RtlCopyMemory(tmp, stk, cap * sizeof(DEL_FRAME));
                        RtlZeroMemory(tmp + cap, (ncap - cap) * sizeof(DEL_FRAME));
                        ExFreePoolWithTag(stk, ART_TAG);
                        stk = tmp; cap = ncap;
                    }
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        case NODE16: {
            ART_NODE16* p = (ART_NODE16*)n;
            USHORT max = min(p->base.num_of_child, 16);
            while (fr->i < max) {
                ART_NODE* ch = p->children[fr->i];
                p->children[fr->i] = NULL;
                fr->i++;
                if (ch) {
                    if (sp >= cap) {
                        SIZE_T ncap = cap * 2;
                        DEL_FRAME* tmp = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ncap * sizeof(DEL_FRAME), ART_TAG);
                        if (!tmp) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
                        RtlCopyMemory(tmp, stk, cap * sizeof(DEL_FRAME));
                        RtlZeroMemory(tmp + cap, (ncap - cap) * sizeof(DEL_FRAME));
                        ExFreePoolWithTag(stk, ART_TAG);
                        stk = tmp; cap = ncap;
                    }
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        case NODE48: {
            ART_NODE48* p = (ART_NODE48*)n;
            while (fr->map_i < 256) {
                UCHAR pos = p->child_index[fr->map_i];
                p->child_index[fr->map_i] = 0;
                fr->map_i++;
                if (pos > 0 && pos <= 48) {
                    ART_NODE* ch = p->children[pos - 1];
                    p->children[pos - 1] = NULL;
                    if (ch) {
                        if (sp >= cap) {
                            SIZE_T ncap = cap * 2;
                            DEL_FRAME* tmp = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ncap * sizeof(DEL_FRAME), ART_TAG);
                            if (!tmp) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
                            RtlCopyMemory(tmp, stk, cap * sizeof(DEL_FRAME));
                            RtlZeroMemory(tmp + cap, (ncap - cap) * sizeof(DEL_FRAME));
                            ExFreePoolWithTag(stk, ART_TAG);
                            stk = tmp; cap = ncap;
                        }
                        stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                        pushed = TRUE;
                        break;
                    }
                }
            }
        } break;

        case NODE256: {
            ART_NODE256* p = (ART_NODE256*)n;
            while (fr->i < 256) {
                ART_NODE* ch = p->children[fr->i];
                p->children[fr->i] = NULL;
                fr->i++;
                if (ch) {
                    if (sp >= cap) {
                        SIZE_T ncap = cap * 2;
                        DEL_FRAME* tmp = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ncap * sizeof(DEL_FRAME), ART_TAG);
                        if (!tmp) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
                        RtlCopyMemory(tmp, stk, cap * sizeof(DEL_FRAME));
                        RtlZeroMemory(tmp + cap, (ncap - cap) * sizeof(DEL_FRAME));
                        ExFreePoolWithTag(stk, ART_TAG);
                        stk = tmp; cap = ncap;
                    }
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        default:
            // Unknown type: just free it as a node below
            break;
        }

        if (!pushed) {
            free_node(&n);
            (*node_count)++; // count freed internal node
            sp--;
        }
    }

done:
    if (stk) ExFreePoolWithTag(stk, ART_TAG);
    *proot = NULL;
    return status;
}

// Deletes the entire subtree whose path matches 'unicode_key' as a prefix.
// Critical order: detach from parent first, then free detached subtree,
// decrementing tree->size by the number of leaves deleted.
NTSTATUS art_delete_subtree(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key) {
    if (!tree || !unicode_key) return STATUS_INVALID_PARAMETER;
    if (tree->size == 0) { DbgPrint("[ART] Tree is empty\n"); return STATUS_NOT_FOUND; }

    USHORT prefix_len = 0;
    PUCHAR prefix = unicode_to_utf8(unicode_key, &prefix_len);
    if (!prefix) return STATUS_INSUFFICIENT_RESOURCES;
    if (prefix_len == 0) { destroy_utf8_key(prefix); return STATUS_INVALID_PARAMETER; }

    ART_NODE** node_ref = &tree->root; // reference to current node pointer
    ART_NODE* node = tree->root;
    ART_NODE* parent = NULL;
    ART_NODE** parent_ref = NULL;
    USHORT depth = 0;
    UCHAR last_key = 0;

    while (node && !IS_LEAF(node)) {
        // Ensure compressed path matches
        if (node->prefix_length > 0) {
            USHORT matched = check_prefix(node, prefix, prefix_len, depth);
            USHORT expected = (USHORT)min(MAX_PREFIX_LENGTH, node->prefix_length);
            if (matched != expected) { destroy_utf8_key(prefix); return STATUS_NOT_FOUND; }

            // For long prefixes, validate the remaining bytes with a representative leaf
            if (node->prefix_length > MAX_PREFIX_LENGTH) {
                // key must be long enough for full prefix
                if ((USHORT)(depth + node->prefix_length) < depth || (depth + node->prefix_length) > prefix_len) {
                    destroy_utf8_key(prefix);
                    return STATUS_NOT_FOUND;
                }
                const ART_LEAF* rep = minimum(node);
                if (!rep) { destroy_utf8_key(prefix); return STATUS_DATA_ERROR; }
                USHORT rem = (USHORT)(node->prefix_length - MAX_PREFIX_LENGTH);
                for (USHORT i = 0; i < rem; ++i) {
                    if (rep->key[depth + MAX_PREFIX_LENGTH + i] != prefix[depth + MAX_PREFIX_LENGTH + i]) {
                        destroy_utf8_key(prefix);
                        return STATUS_NOT_FOUND;
                    }
                }
            }

            if ((USHORT)(depth + node->prefix_length) < depth) { destroy_utf8_key(prefix); return STATUS_INTEGER_OVERFLOW; }
            depth += node->prefix_length;
        }

        // If we've matched exactly the prefix: delete this entire subtree
        if (depth == prefix_len) {
            // 1) Detach from parent *first* so parent can shrink/collapse
            ART_NODE* to_free = node;
            NTSTATUS st;
            if (parent && parent_ref) {
                if (parent->type == NODE4 || parent->type == NODE16) {
                    // For NODE4/16 we must pass the address of the child's slot as 'leaf'
                    st = remove_child(parent, parent_ref, 0, node_ref);
                }
                else {
                    // NODE48/256 remove by key byte
                    st = remove_child(parent, parent_ref, last_key, NULL);
                }
                if (!NT_SUCCESS(st)) { destroy_utf8_key(prefix); return st; }
            }
            else {
                // It was the root
                *node_ref = NULL;
                tree->root = NULL;
            }

            // 2) Free the detached subtree and count leaves (keys)
            ULONG leaves = 0, nodes = 0;
            NTSTATUS st2 = recursive_delete_all_internal(tree, to_free, &leaves, &nodes, 0);
            if (!NT_SUCCESS(st2)) {
                // Deep trees may overflow recursion; enforce deletion iteratively.
                ULONG forced_leaves = 0, forced_nodes = 0;
                NTSTATUS st3 = force_delete_all_iterative(&forced_leaves, &forced_nodes, &to_free);
                if (!NT_SUCCESS(st3)) {
                    DbgPrint("[ART] Warning: Iterative cleanup failed with status 0x%X\n", st3);
                    // Silmeyi garantileyemiyorsak (çok nadir), en azından referansı boşaltmış durumdayız.
                    // Bu noktada geri dönmek mantıklı.
                    destroy_utf8_key(prefix);
                    return st3;
                }
                // Başarılı iterative silme , tree->size'ı yaprak sayısı kadar azalt
                if (tree->size >= forced_leaves) tree->size -= forced_leaves; else tree->size = 0;
            }
            else {
                // recursion path: leaves sayıldı
                if (tree->size >= leaves) tree->size -= leaves; else tree->size = 0;
            }

            destroy_utf8_key(prefix);
            return STATUS_SUCCESS;
        }

        if (depth >= prefix_len) { destroy_utf8_key(prefix); return STATUS_NOT_FOUND; }

        // Descend to the next child along the prefix path
        last_key = prefix[depth];
        ART_NODE** child = find_child(node, last_key);
        if (!child || !*child) { destroy_utf8_key(prefix); return STATUS_NOT_FOUND; }

        parent = node;
        parent_ref = node_ref;
        node_ref = child;
        node = *child;
        depth++;
    }

    // Leaf case: exact prefix equals a stored full key
    if (node && IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) { destroy_utf8_key(prefix); return STATUS_DATA_ERROR; }

        if (leaf_matches(leaf, prefix, prefix_len)) {
            NTSTATUS st;
            if (parent && parent_ref) {
                if (parent->type == NODE4 || parent->type == NODE16)
                    st = remove_child(parent, parent_ref, 0, node_ref);
                else
                    st = remove_child(parent, parent_ref, last_key, NULL);
                if (!NT_SUCCESS(st)) { destroy_utf8_key(prefix); return st; }
            }
            else {
                tree->root = NULL;
            }

            // Free the leaf and update size (keys == leaves)
            free_leaf(&leaf);
            if (tree->size > 0) tree->size--;
            destroy_utf8_key(prefix);
            return STATUS_SUCCESS;
        }
    }

    destroy_utf8_key(prefix);
    return STATUS_NOT_FOUND;
}

NTSTATUS art_destroy_tree(_Inout_ ART_TREE* tree) {
    if (!tree) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!tree->root) {
        tree->size = 0;
        return STATUS_SUCCESS;
    }

    ULONG leaf_count = 0, node_count = 0;
    NTSTATUS st = recursive_delete_all_internal(tree, tree->root, &leaf_count, &node_count, 0);

    // Fallback sayaçları
    ULONG forced_leaves = 0;
    ULONG forced_nodes = 0;

    if (!NT_SUCCESS(st)) {
        // Derinlik vb. sebeple recursion başarısız oldu → iteratif temizle
        NTSTATUS st2 = force_delete_all_iterative(&forced_leaves, &forced_nodes, &tree->root);
        if (!NT_SUCCESS(st2)) {
            DbgPrint("[ART] Warning: Iterative cleanup failed with status 0x%X\n", st2);
        }
    }
    else {
        // recursive yol kökü zaten free etti
        tree->root = NULL;
    }

    // Ağaç yok edildi
    tree->size = 0;

    DbgPrint("[ART] Tree destroyed. Recursion(status=0x%X): freed leaves=%lu, nodes=%lu; "
        "iterative_fallback(leaves=%lu, nodes=%lu)\n",
        st, leaf_count, node_count, forced_leaves, forced_nodes);

    return st;
}


/** SEARCH Functions */
ULONG art_search(_In_ CONST ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key) {
    USHORT key_length = 0;
    PUCHAR key = NULL;
    ULONG access_right = POLICY_NONE;
    ART_NODE** child = NULL;
    ART_NODE* node = NULL;
    USHORT prefix_len = 0;
    USHORT depth = 0;
    USHORT search_depth = 0;
    ART_LEAF* leaf = NULL;

    if (!tree || !unicode_key) {
        return POLICY_NONE;
    }

    if (!tree->root || tree->size == 0) {
        DbgPrint("[ART] Search on empty tree\n");
        return POLICY_NONE;
    }

    key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        DbgPrint("[ART] Failed to convert Unicode key\n");
        return POLICY_NONE;
    }

    if (key_length == 0) {
        DbgPrint("[ART] Empty key after conversion\n");
        destroy_utf8_key(key);
        return POLICY_NONE;
    }

    node = tree->root;

    while (node && search_depth < MAX_RECURSION_DEPTH) {
        search_depth++;

        if (IS_LEAF(node)) {
            leaf = LEAF_RAW(node);
            if (!leaf) {
                DbgPrint("[ART] Invalid leaf node detected\n");
            }
            else if (leaf_matches(leaf, key, key_length)) {
                access_right = leaf->value;
                DbgPrint("[ART] Key found with value: %lu\n", access_right);
            }
            else {
                DbgPrint("[ART] Leaf found but key doesn't match\n");
            }
            break;
        }

        if (node->prefix_length > 0) {
            if (depth >= key_length) {
                DbgPrint("[ART] Key too short for prefix\n");
                break;
            }

            prefix_len = check_prefix(node, key, key_length, depth);
            USHORT expected_prefix = (USHORT)min(MAX_PREFIX_LENGTH, node->prefix_length);

            if (prefix_len != expected_prefix) {
                DbgPrint("[ART] Prefix mismatch at depth %u\n", depth);
                break;
            }

            // If the node's prefix is longer than MAX_PREFIX_LENGTH, validate remaining bytes
            // using a representative leaf. Also ensure key is long enough for full prefix.
            if (node->prefix_length > MAX_PREFIX_LENGTH) {
                if ((USHORT)(depth + node->prefix_length) < depth || (depth + node->prefix_length) > key_length) {
                    DbgPrint("[ART] Prefix exceeds key length during search\n");
                    break;
                }

                const ART_LEAF* rep = minimum(node);
                if (!rep) {
                    DbgPrint("[ART] Could not fetch representative leaf for long-prefix compare\n");
                    break;
                }
                // *** EK KONTROL: rep->key ve uzunluğu yeterli mi? ***
                if (!rep->key || rep->key_length < (USHORT)(depth + node->prefix_length)) {
                    DbgPrint("[ART] Representative leaf key too short for long-prefix compare\n");
                    break;
                }

                USHORT rem = (USHORT)(node->prefix_length - MAX_PREFIX_LENGTH);
                for (USHORT i = 0; i < rem; ++i) {
                    if (rep->key[depth + MAX_PREFIX_LENGTH + i] != key[depth + MAX_PREFIX_LENGTH + i]) {
                        DbgPrint("[ART] Long-prefix mismatch during search\n");
                        goto search_break;
                    }
                }
            }

            if ((USHORT)(depth + node->prefix_length) < depth) {
                DbgPrint("[ART] Depth overflow detected\n");
                break;
            }

            depth += node->prefix_length;
        }

        // If the key ends exactly at this internal node, check the 0x00 terminator edge.
        if (depth == key_length) {
            ART_NODE** term = find_child(node, 0);
            if (term && *term) {
                if (!IS_LEAF(*term)) {
                    DbgPrint("[ART] Terminator edge is not a leaf\n");
                    break;
                }
                ART_LEAF* tleaf = LEAF_RAW(*term);
                if (!tleaf) {
                    DbgPrint("[ART] Invalid terminator leaf\n");
                    break;
                }
                if (leaf_matches(tleaf, key, key_length)) {
                    access_right = tleaf->value;
                    DbgPrint("[ART] Key found via terminator with value: %lu\n", access_right);
                }
            }
            else {
                DbgPrint("[ART] Key exhausted before reaching leaf (no terminator)\n");
            }
            break;
        }

        child = find_child(node, key[depth]);
        if (!child || !*child) {
            DbgPrint("[ART] Child not found for key byte: %u\n", key[depth]);
            break;
        }

        node = *child;
        depth++;
        continue;

    search_break:
        break;
    }

    if (search_depth >= MAX_RECURSION_DEPTH) {
        DbgPrint("[ART] Search depth exceeded maximum limit\n");
    }

    destroy_utf8_key(key);

    return access_right;
}
