#include "adaptive_radix_tree.h"

#include "log.h"

#include <ntifs.h>
#include <intrin.h> // For _mm_cmpeq_epi8, _mm_movemask_epi8


#define IS_LEAF(x) (((uintptr_t)x & 1))
#define SET_LEAF(x) ((VOID*)((uintptr_t)x | 1))
#define LEAF_RAW(x) ((ART_LEAF*)((VOID*)((uintptr_t)x & ~1)))

#define ART_TAG 'trAd'

ART_TREE* g_art_tree = NULL;

static inline PUCHAR unicode_to_utf8(PCUNICODE_STRING unicode, PSIZE_T out_length) {
    NTSTATUS status;

    if (!unicode || !out_length) {
        return NULL;
    }

    // query the size needed for conversion
    ULONG required_length = 0;
    status = RtlUnicodeToUTF8N(NULL, 0, &required_length, unicode->Buffer, unicode->Length);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    PUCHAR utf8_key = ExAllocatePool2(POOL_FLAG_NON_PAGED, required_length + 1, ART_TAG);
    if (!utf8_key) {
        return NULL;
    }

    // Perform actual conversion
    ULONG written_length = 0;
    status = RtlUnicodeToUTF8N(
        (PCHAR)utf8_key,
        (ULONG)required_length,
        &written_length,
        unicode->Buffer,
        unicode->Length
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(utf8_key, ART_TAG);
        return NULL;
    }

    *out_length = written_length;
    utf8_key[written_length] = '\0';
    return utf8_key;
}

static inline VOID destroy_utf8_key(PUCHAR key) {
    if (key) {
        ExFreePoolWithTag(key, ART_TAG);
        key = NULL;
    }
}

static inline free_node(ART_NODE* node) {
    if (node) {
        ExFreePoolWithTag(node, ART_TAG);
        node = NULL;
    }
}

static ART_NODE* art_create_node(NODE_TYPE type) {
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

    ART_NODE* node = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, ART_TAG);
    if (!node) {
        LOG_MSG("art_create_node: Allocation failed for size %llu\n", size);
        return NULL;
    }

    RtlZeroMemory(node, size);
    node->prefix_length = 0;
    node->type = type;
    node->num_of_child = 0;

    return node;
}

int art_init_tree(ART_TREE* tree) {
    tree->root = NULL;
    tree->size = 0;
    return 0;
}

static VOID art_destroy_node(ART_NODE* node) {
    if (!node) {
        return;
    }

    if (IS_LEAF(node)) {
        ExFreePoolWithTag(LEAF_RAW(node), ART_TAG);
        return;
    }

    switch (node->type) {
    case NODE4: {
        ART_NODE4* n = (ART_NODE4*)node;
        for (USHORT i = 0; i < node->num_of_child; i++) {
            art_destroy_node(n->children[i]);
        }
        break;
    }
    case NODE16: {
        ART_NODE16* n = (ART_NODE16*)node;
        for (USHORT i = 0; i < node->num_of_child; i++) {
            art_destroy_node(n->children[i]);
        }
        break;
    }
    case NODE48: {
        ART_NODE48* n = (ART_NODE48*)node;
        for (USHORT i = 0; i < 256; i++) {
            UCHAR idx = n->child_index[i];
            if (idx) {
                art_destroy_node(n->children[idx - 1]);
            }
        }
        break;
    }
    case NODE256: {
        ART_NODE256* n = (ART_NODE256*)node;
        for (USHORT i = 0; i < 256; i++) {
            if (n->children[i]) {
                art_destroy_node(n->children[i]);
            }
        }
        break;
    }
    default:
        // Unexpected node type, just free
        break;
    }

    free_node(node);
}

int art_destroy_tree(ART_TREE* tree) {
    art_destroy_node(tree->root);
    return 0;
}


/** COMMON Local Functions */
static SIZE_T leaf_matches(CONST ART_LEAF* leaf, CONST PUCHAR key, SIZE_T key_length, USHORT depth) {
    (VOID)depth;
    // Fail if the key lengths are different
    if (leaf->key_length != (UINT32)key_length) {
        return 1;
    }

    // Compare the keys starting at the depth
    return RtlCompareMemory(leaf->key, key, key_length);
}

static inline unsigned ctz(UINT32 x) {
    unsigned long index;
    if (_BitScanForward(&index, x)) {
        return (unsigned)index;
    }
    else {
        return 32; // undefined for zero, handle appropriately
    }
}

static ART_NODE** find_child(ART_NODE* node, UCHAR c) {
    int mask, bitfield;

    switch (node->type) {
    case NODE4:
    {
        ART_NODE4* node4 = (ART_NODE4*)node;
        for (int i = 0; i < node->num_of_child; i++) {
            if (node4->keys[i] == c) {
                return &node4->children[i];
            }
        }
        break;
    }

    case NODE16:
    {
        ART_NODE16* node16 = (ART_NODE16*)node;

        // Compare the key to all 16 stored keys
        bitfield = 0;
        for (int i = 0; i < 16; ++i) {
            if (node16->keys[i] == c) {
                bitfield |= (1 << i); // set bit i 
            }
        }

        // Use a mask to ignore children that don't exist
        mask = (1 << node->num_of_child) - 1;
        bitfield &= mask;

        /*
         * If we have a match (any bit set) then we can
         * return the pointer match using ctz to get
         * the index.
         */
        if (bitfield) {
            return &node16->children[ctz(bitfield)];
        }
        break;
    }

    case NODE48:
    {
        ART_NODE48* node48 = (ART_NODE48*)node;
        int index = node48->child_index[c];
        if (index) {
            return &node48->children[index - 1];
        }
        break;
    }

    case NODE256:
    {
        ART_NODE256* node256 = (ART_NODE256*)node;
        if (node256->children[c]) {
            return &node256->children[c];
        }
        break;
    }

    default:
        LOG_MSG("Unexpected NODE type !");
    }

    return NULL;
}

static VOID copy_header(ART_NODE* dest, ART_NODE* src) {
    dest->num_of_child = src->num_of_child;
    dest->prefix_length = src->prefix_length;
    RtlCopyMemory(dest->prefix, src->prefix, min(MAX_PREFIX_LENGTH, src->prefix_length));
}

static USHORT check_prefix(CONST ART_NODE* node, CONST PUCHAR key, SIZE_T key_length, USHORT depth) {
    USHORT maximum_prefix_length = min(min(node->prefix_length, MAX_PREFIX_LENGTH), (USHORT)key_length - depth);

    for (USHORT index = 0; index < maximum_prefix_length; index++) {
        if (node->prefix[index] != key[depth + index]) {
            return index;
        }
    }
    return maximum_prefix_length;
}

/** INSERT Functions */

// Find the minimum leaf under a node
static ART_LEAF* minimum(CONST ART_NODE* node) {
    if (!node) {
        return NULL;
    }

    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    int index;
    switch (node->type) {
    case NODE4:
        // In NODE4, children are stored in sorted order of keys.
        // The leftmost child(children[0]) has the minimum key.
        return minimum(((CONST ART_NODE4*)node)->children[0]);

    case NODE16:
        // In NODE16, children are stored in sorted order of keys.
        // The leftmost child(children[0]) has the minimum key.
        return minimum(((CONST ART_NODE16*)node)->children[0]);

    case NODE48:
    {
        // NODE48 uses a 256-entry child_index mapping each byte value to a child index (+1).
        // Start from index = 0 and find the first non-zero mapping, corresponding to the smallest key.
        index = 0;
        while (!((CONST ART_NODE48*)node)->child_index[index]) {
            index++;
        }
        index = ((CONST ART_NODE48*)node)->child_index[index] - 1;
        return minimum(((CONST ART_NODE48*)node)->children[index]);
    }

    case NODE256:
    {
        // Start from index = 0 and find the first non - NULL child.
        index = 0;
        while (!((CONST ART_NODE256*)node)->children[index]) {
            index++;
        }
        return minimum(((CONST ART_NODE256*)node)->children[index]);
    }

    default:
        LOG_MSG("Unexpected NODE type!");
        return NULL;
    }
}

// Find the maximum leaf under a node
static ART_LEAF* maximum(CONST ART_NODE* node) {
    // Handle base cases
    if (!node) {
        return NULL;
    }

    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    int index;
    switch (node->type) {
    case NODE4:
        return maximum(((CONST ART_NODE4*)node)->children[node->num_of_child - 1]);

    case NODE16:
        return maximum(((CONST ART_NODE16*)node)->children[node->num_of_child - 1]);

    case NODE48:
    {
        index = 255;
        while (!((CONST ART_NODE48*)node)->child_index[index]) {
            index--;
        }
        index = ((CONST ART_NODE48*)node)->child_index[index] - 1;
        return maximum(((CONST ART_NODE48*)node)->children[index]);
    }

    case NODE256:
    {
        index = 255;
        while (!((CONST ART_NODE256*)node)->children[index]) {
            index--;
        }
        return maximum(((CONST ART_NODE256*)node)->children[index]);
    }

    default:
        LOG_MSG("Unexpected NODE type!");
        return NULL;
    }
}

ART_LEAF* art_minimum(ART_TREE* t) {
    return minimum((ART_NODE*)t->root);
}

ART_LEAF* art_maximum(ART_TREE* t) {
    return maximum((ART_NODE*)t->root);
}

static ART_LEAF* make_leaf(CONST PUCHAR key, SIZE_T key_length, VOID* value) {
    ART_LEAF* leaf = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ART_LEAF) + key_length, ART_TAG);
    if (leaf) {
        RtlZeroMemory(leaf, sizeof(ART_LEAF) + key_length);
        leaf->value = value;
        leaf->key_length = (UINT32)key_length;
        RtlCopyMemory(leaf->key, key, key_length);
    }
    return leaf;
}

static USHORT longest_common_prefix(ART_LEAF* leaf1, ART_LEAF* leaf2, USHORT depth) {
    USHORT max_key_length = (USHORT)(min(leaf1->key_length, leaf2->key_length)) - depth;

    for (USHORT index = 0; index < max_key_length; index++) {
        if (leaf1->key[depth + index] != leaf2->key[depth + index])
            return index;
    }
    return max_key_length;
}

static USHORT prefix_mismatch(CONST ART_NODE* node, CONST PUCHAR key, SIZE_T key_length, USHORT depth) {
#pragma warning( push )
#pragma warning( disable : 4018 ) // '<': signed/unsigned mismatch
    UINT32 maximum_prefix_length = min(min(MAX_PREFIX_LENGTH, node->prefix_length), (UINT32)key_length - depth);
#pragma warning( pop )
    USHORT index;
    for (index = 0; index < maximum_prefix_length; index++) {
        if (node->prefix[index] != key[depth + index])
            return index;
    }

    // If the prefix is short we can aVOID finding a leaf
    if (node->prefix_length > MAX_PREFIX_LENGTH) {
        // Prefix is longer than what we've checked, find a leaf
        ART_LEAF* leaf = minimum(node);
        maximum_prefix_length = min(leaf->key_length, (UINT32)key_length) - depth;
        for (; index < maximum_prefix_length; index++) {
            if (leaf->key[index + depth] != key[depth + index]) {
                return index;
            }
        }
    }
    return index;
}

static UINT8 add_child256(ART_NODE256* node, ART_NODE** ref, UCHAR c, VOID* child) {
    (VOID)ref;
    node->base.num_of_child++;
    node->children[c] = (ART_NODE*)child;
    return 0;
}

static UINT8 add_child48(ART_NODE48* node, ART_NODE** ref, UCHAR c, VOID* child) {
    if (node->base.num_of_child < 48) {
        UINT8 pos = 0;
        while (node->children[pos]) {
            pos++;
        }
        node->children[pos] = (ART_NODE*)child;
        node->child_index[c] = pos + 1;
        node->base.num_of_child++;
    }
    else {
        ART_NODE256* new_node = (ART_NODE256*)art_create_node(NODE256);
        for (int i = 0; i < 256; i++) {
            if (node->child_index[i]) {
                new_node->children[i] = node->children[node->child_index[i] - 1];
            }
        }
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE*)node);
        add_child256(new_node, ref, c, child);
    }
    return 0;
}

static UINT8 add_child16(ART_NODE16* node, ART_NODE** ref, UCHAR c, VOID* child) {
    if (node->base.num_of_child < 16) {
        // Used to mask out bits for positions beyond existing children
        unsigned mask = (1 << node->base.num_of_child) - 1;

        // Compare the key to all 16 stored keys
        unsigned bitfield = 0;
        for (short i = 0; i < 16; ++i) {
            if (c < node->keys[i])
                bitfield |= (1 << i);
        }

        // Use a mask to ignore children that don't exist
        bitfield &= mask;

        // Check if less than any
        unsigned idx;
        if (bitfield) {
            idx = ctz(bitfield);
            RtlMoveMemory(node->keys + idx + 1, node->keys + idx, node->base.num_of_child - idx);
            RtlMoveMemory(node->children + idx + 1, node->children + idx, (node->base.num_of_child - idx) * sizeof(VOID*));
        }
        else {
            idx = node->base.num_of_child;
        }

        // Set the child
        node->keys[idx] = c;
        node->children[idx] = (ART_NODE*)child;
        node->base.num_of_child++;

    }
    else {
        ART_NODE48* new_node = (ART_NODE48*)art_create_node(NODE48);

        // Copy the child pointers and populate the key map
        RtlCopyMemory(new_node->children, node->children, sizeof(VOID*) * node->base.num_of_child);
        for (UINT8 i = 0; i < node->base.num_of_child; i++) {
            new_node->child_index[node->keys[i]] = i + 1;
        }
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE*)node);
        add_child48(new_node, ref, c, child);
    }
    return 0;
}

static UINT8 add_child4(ART_NODE4* node, ART_NODE** ref, UCHAR c, VOID* child) {
    if (node->base.num_of_child < 4) {
        int idx;
        for (idx = 0; idx < node->base.num_of_child; idx++) {
            if (c < node->keys[idx]) {
                break;
            }
        }

        // Shift to make room
        RtlMoveMemory(node->keys + idx + 1, node->keys + idx, node->base.num_of_child - idx);
        RtlMoveMemory(node->children + idx + 1, node->children + idx, (node->base.num_of_child - idx) * sizeof(VOID*));

        // Insert element
        node->keys[idx] = c;
        node->children[idx] = (ART_NODE*)child;
        node->base.num_of_child++;

    }
    else {
        ART_NODE16* new_node = (ART_NODE16*)art_create_node(NODE16);

        // Copy the child pointers and the key map
        RtlCopyMemory(new_node->children, node->children, sizeof(VOID*) * node->base.num_of_child);
        RtlCopyMemory(new_node->keys, node->keys, sizeof(UCHAR) * node->base.num_of_child);
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE*)node);
        add_child16(new_node, ref, c, child);
    }
    return 0;
}

static UINT8 add_child(ART_NODE* node, ART_NODE** ref, UCHAR c, VOID* child) {
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
        LOG_MSG("Unexpected NODE type!");
    }
    return 0;
}

static VOID* recursive_insert(ART_NODE* node, ART_NODE** ref, CONST PUCHAR key, SIZE_T key_length, VOID* value, USHORT depth, int* old, int replace) {
    // If we are at a NULL node, inject a leaf
    if (!node) {
        *ref = (ART_NODE*)SET_LEAF(make_leaf(key, key_length, value));
        return NULL;
    }

    // If we are at a leaf, we need to replace it with a node
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);

        // Check if we are updating an existing value
        if (!leaf_matches(leaf, key, key_length, depth)) {
            *old = 1;
            VOID* old_val = leaf->value;
            if (replace) {
                leaf->value = value;
            }
            return old_val;
        }

        // New value, we must split the leaf into a node4
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);

        // Create a new leaf
        ART_LEAF* new_leaf = make_leaf(key, key_length, value);

        // Determine longest prefix
        USHORT longest_prefix = longest_common_prefix(leaf, new_leaf, depth);
        new_node->base.prefix_length = longest_prefix;
        RtlCopyMemory(new_node->base.prefix, key + depth, min(MAX_PREFIX_LENGTH, longest_prefix));
        // Add the leafs to the new node4
        *ref = (ART_NODE*)new_node;
        add_child4(new_node, ref, leaf->key[depth + longest_prefix], SET_LEAF(leaf));
        add_child4(new_node, ref, new_leaf->key[depth + longest_prefix], SET_LEAF(new_leaf));
        return NULL;
    }

    // Check if given node has a prefix
    if (node->prefix_length) {
        // Determine if the prefixes differ, since we need to split
        USHORT prefix_diff = prefix_mismatch(node, key, key_length, depth);
        if ((UINT32)prefix_diff >= node->prefix_length) {
            depth += node->prefix_length;
            goto RECURSE_SEARCH;
        }

        // Create a new node
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
        *ref = (ART_NODE*)new_node;
        new_node->base.prefix_length = prefix_diff;
        RtlCopyMemory(new_node->base.prefix, node->prefix, min(MAX_PREFIX_LENGTH, prefix_diff));

        // Adjust the prefix of the old node
        if (node->prefix_length <= MAX_PREFIX_LENGTH) {
#pragma warning( push )
#pragma warning( disable : 6385 ) // Reading invalid data from 'node->prefix': the readable size is '23' bytes, but 'prefix_diff' bytes may be read.
            add_child4(new_node, ref, node->prefix[prefix_diff], node);
#pragma warning( pop )
            node->prefix_length -= (prefix_diff + 1);
            RtlMoveMemory(node->prefix, node->prefix + prefix_diff + 1, min(MAX_PREFIX_LENGTH, node->prefix_length));
        }
        else {
            node->prefix_length -= (prefix_diff + 1);
            ART_LEAF* l = minimum(node);
            add_child4(new_node, ref, l->key[depth + prefix_diff], node);
            RtlCopyMemory(node->prefix, l->key + depth + prefix_diff + 1, min(MAX_PREFIX_LENGTH, node->prefix_length));
        }

        // Insert the new leaf
        ART_LEAF* leaf = make_leaf(key, key_length, value);
        add_child4(new_node, ref, key[depth + prefix_diff], SET_LEAF(leaf));
        return NULL;
    }

RECURSE_SEARCH:;

    // Find a child to recurse to
    ART_NODE** child = find_child(node, key[depth]);
    if (child) {
        return recursive_insert(*child, child, key, key_length, value, depth + 1, old, replace);
    }

    // No child, node goes within us
    ART_LEAF* leaf = make_leaf(key, key_length, value);
    add_child(node, ref, key[depth], SET_LEAF(leaf));
    return NULL;
}

VOID* art_insert(ART_TREE* tree, PCUNICODE_STRING unicode_key, VOID* value) {
    SIZE_T key_length;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);

    int old_value = 0;
    VOID* old = recursive_insert(tree->root, &tree->root, key, key_length, value, 0, &old_value, 1);
    if (!old_value) {
        tree->size++;
    }

    destroy_utf8_key(key);
    return old;
}

VOID* art_insert_no_replace(ART_TREE* tree, PCUNICODE_STRING unicode_key, VOID* value) {
    SIZE_T key_length;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);

    int old_val = 0;
    VOID* old = recursive_insert(tree->root, &tree->root, key, key_length, value, 0, &old_val, 0);
    if (!old_val) {
        tree->size++;
    }

    destroy_utf8_key(key);
    return old;
}


/** REMOVE Functions*/
static UINT8 remove_child256(ART_NODE256* node, ART_NODE** ref, UCHAR c) {
    node->children[c] = NULL;
    node->base.num_of_child--;

    // Resize to a node48 on underflow, not immediately to prevent
    // trashing if we sit on the 48/49 boundary
    if (node->base.num_of_child == 37) {
        ART_NODE48* new_node = (ART_NODE48*)art_create_node(NODE48);
        *ref = (ART_NODE*)new_node;
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);

        USHORT pos = 0;
        for (USHORT i = 0; i < 256; i++) {
            if (node->children[i]) {
                new_node->children[pos] = node->children[i];
                new_node->child_index[i] = (UCHAR)(pos + 1);
                pos++;
            }
        }
        free_node((ART_NODE*)node);
    }
    return 0;
}

static UINT8 remove_child48(ART_NODE48* node, ART_NODE** ref, UCHAR c) {
    int pos = node->child_index[c];
    node->child_index[c] = 0;
    node->children[pos - 1] = NULL;
    node->base.num_of_child--;

    if (node->base.num_of_child == 12) {
        ART_NODE16* new_node = (ART_NODE16*)art_create_node(NODE16);
        *ref = (ART_NODE*)new_node;
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);

        USHORT child = 0;
        for (USHORT i = 0; i < 256; i++) {
            pos = node->child_index[i];
            if (pos) {
                new_node->keys[child] = (UCHAR)i;
                new_node->children[child] = node->children[pos - 1];
                child++;
            }
        }
        free_node((ART_NODE*)node);
    }
    return 0;
}

static UINT8 remove_child16(ART_NODE16* node, ART_NODE** ref, ART_NODE** leaf) {
    UINT64 pos = leaf - node->children;
    RtlMoveMemory(node->keys + pos, node->keys + pos + 1, node->base.num_of_child - 1 - pos);
    RtlMoveMemory(node->children + pos, node->children + pos + 1, (node->base.num_of_child - 1 - pos) * sizeof(VOID*));
    node->base.num_of_child--;

    if (node->base.num_of_child == 3) {
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
        *ref = (ART_NODE*)new_node;
        copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        RtlCopyMemory(new_node->keys, node->keys, 4);
        RtlCopyMemory(new_node->children, node->children, 4 * sizeof(VOID*));
        free_node((ART_NODE*)node);
    }
    return 0;
}

static UINT8 remove_child4(ART_NODE4* node, ART_NODE** ref, ART_NODE** leaf) {
    UINT64 pos = leaf - node->children;
    RtlMoveMemory(node->keys + pos, node->keys + pos + 1, node->base.num_of_child - 1 - pos);
    RtlMoveMemory(node->children + pos, node->children + pos + 1, (node->base.num_of_child - 1 - pos) * sizeof(VOID*));
    node->base.num_of_child--;

    // Remove nodes with only a single child
    if (node->base.num_of_child == 1) {
        ART_NODE* child = node->children[0];
        if (!IS_LEAF(child)) {
            // Concatenate the prefixes
            int prefix = node->base.prefix_length;
            if (prefix < MAX_PREFIX_LENGTH) {
                node->base.prefix[prefix] = node->keys[0];
                prefix++;
            }
            if (prefix < MAX_PREFIX_LENGTH) {
                int sub_prefix = min(child->prefix_length, MAX_PREFIX_LENGTH - prefix);
                RtlCopyMemory(node->base.prefix + prefix, child->prefix, sub_prefix);
                prefix += sub_prefix;
            }

            // Store the prefix in the child
            RtlCopyMemory(child->prefix, node->base.prefix, min(prefix, MAX_PREFIX_LENGTH));
            child->prefix_length += node->base.prefix_length + 1;
        }
        *ref = child;
        free_node((ART_NODE*)node);
    }
    return 0;
}

static UINT8 remove_child(ART_NODE* node, ART_NODE** ref, UCHAR c, ART_NODE** l) {
    switch (node->type) {
    case NODE4:
        return remove_child4((ART_NODE4*)node, ref, l);
    case NODE16:
        return remove_child16((ART_NODE16*)node, ref, l);
    case NODE48:
        return remove_child48((ART_NODE48*)node, ref, c);
    case NODE256:
        return remove_child256((ART_NODE256*)node, ref, c);
    default:
        LOG_MSG("Unexpected NODE type!");
    }
    return 0;
}

static ART_LEAF* recursive_delete(ART_NODE* node, ART_NODE** ref, CONST PUCHAR key, SIZE_T key_length, USHORT depth) {
    // Search terminated
    if (!node) {
        return NULL;
    }

    // Handle hitting a leaf node
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf_matches(leaf, key, key_length, depth)) {
            *ref = NULL;
            return leaf;
        }
        return NULL;
    }

    // Bail if the prefix does not match
    if (node->prefix_length) {
        int common_prefix_length = check_prefix(node, key, key_length, depth);
        if (common_prefix_length != min(MAX_PREFIX_LENGTH, node->prefix_length)) {
            return NULL;
        }
        depth = depth + node->prefix_length;
    }

    // Find child node
    ART_NODE** child = find_child(node, key[depth]);
    if (!child) {
        return NULL;
    }

    // If the child is leaf, delete from this node
    if (IS_LEAF(*child)) {
        ART_LEAF* leaf = LEAF_RAW(*child);
        if (!leaf_matches(leaf, key, key_length, depth)) {
            remove_child(node, ref, key[depth], child);
            return leaf;
        }
        return NULL;

        // Recurse
    }
    else {
        return recursive_delete(*child, child, key, key_length, depth + 1);
    }
}

VOID* art_delete(ART_TREE* tree, PCUNICODE_STRING unicode_key) {
    SIZE_T key_length;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);

    ART_LEAF* leaf = recursive_delete(tree->root, &tree->root, key, key_length, 0);
    if (leaf) {
        tree->size--;
        VOID* old = leaf->value;
        ExFreePoolWithTag(leaf, ART_TAG);

        destroy_utf8_key(key);
        return old;
    }

    destroy_utf8_key(key);
    return NULL;
}

/** SEARCH Functions */
VOID* art_search(CONST ART_TREE* tree, PCUNICODE_STRING unicode_key) {
    SIZE_T key_length;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);

    ART_NODE** child;
    ART_NODE* node = tree->root;
    USHORT prefix_len, depth = 0;
    while (node) {
        // Might be a leaf
        if (IS_LEAF(node)) {
            node = (ART_NODE*)LEAF_RAW(node);
            // Check if the expanded path matches
            if (!leaf_matches((ART_LEAF*)node, key, key_length, depth)) {
                destroy_utf8_key(key);
                return ((ART_LEAF*)node)->value;
            }

            destroy_utf8_key(key);
            return NULL;
        }

        //  If the node has a prefix, check if it matches the key at the current depth
        if (node->prefix_length) {
            prefix_len = check_prefix(node, key, key_length, depth);
            if (prefix_len != min(MAX_PREFIX_LENGTH, node->prefix_length)) {
                destroy_utf8_key(key);
                return NULL;
            }
            depth = depth + node->prefix_length;
        }

        // Recursively search
        child = find_child(node, key[depth]);
        node = (child) ? *child : NULL;
        depth++;
    }

    destroy_utf8_key(key);
    return NULL;
}

/** ITERATION Functions */
static int recursive_iter(ART_NODE* node, art_callback callback, VOID* data) {
    // Handle base cases
    if (!node) {
        return 0;
    }

    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        return callback(data, (CONST PUCHAR)leaf->key, leaf->key_length, leaf->value);
    }

    int index, res;
    switch (node->type) {
    case NODE4:
    {
        for (int i = 0; i < node->num_of_child; i++) {
            res = recursive_iter(((ART_NODE4*)node)->children[i], callback, data);
            if (res) {
                return res;
            }
        }
        break;
    }

    case NODE16:
    {
        for (int i = 0; i < node->num_of_child; i++) {
            res = recursive_iter(((ART_NODE16*)node)->children[i], callback, data);
            if (res) {
                return res;
            }
        }
        break;
    }

    case NODE48:
    {
        for (int i = 0; i < 256; i++) {
            index = ((ART_NODE48*)node)->child_index[i];
            if (!index) {
                continue;
            }

            res = recursive_iter(((ART_NODE48*)node)->children[index - 1], callback, data);
            if (res) {
                return res;
            }
        }
        break;
    }

    case NODE256:
    {
        for (int i = 0; i < 256; i++) {
            if (!((ART_NODE256*)node)->children[i]) {
                continue;
            }

            res = recursive_iter(((ART_NODE256*)node)->children[i], callback, data);
            if (res) {
                return res;
            }
        }
        break;
    }

    default:
        LOG_MSG("Unexpected NODE type!");
    }

    return 0;
}

int art_iter(ART_TREE* tree, art_callback callback, VOID* data) {
    return recursive_iter(tree->root, callback, data);
}

static SIZE_T leaf_prefix_matches(CONST ART_LEAF* node, CONST PUCHAR prefix, SIZE_T prefix_len) {
    // Fail if the key length is too short
    if (node->key_length < (UINT32)prefix_len) {
        return 1;
    }

    // Compare the keys
    return RtlCompareMemory(node->key, prefix, prefix_len);
}

int art_iter_prefix(ART_TREE* tree, CONST PUCHAR key, SIZE_T key_length, art_callback callback, VOID* data) {
    ART_NODE** child;
    ART_NODE* node = tree->root;
    SHORT prefix_len, depth = 0;
    while (node) {
        // Might be a leaf
        if (IS_LEAF(node)) {
            node = (ART_NODE*)LEAF_RAW(node);
            // Check if the expanded path matches
            if (!leaf_prefix_matches((ART_LEAF*)node, key, key_length)) {
                ART_LEAF* leaf = (ART_LEAF*)node;
                return callback(data, (CONST PUCHAR)leaf->key, leaf->key_length, leaf->value);
            }
            return 0;
        }

        // If the depth matches the prefix, we need to handle this node
        if (depth == key_length) {
            ART_LEAF* leaf = minimum(node);
            if (!leaf_prefix_matches(leaf, key, key_length)) {
                return recursive_iter(node, callback, data);
            }
            return 0;
        }

        // Bail if the prefix does not match
        if (node->prefix_length) {
            prefix_len = prefix_mismatch(node, key, key_length, depth);

            // Guard if the mis-match is longer than the MAX_PREFIX_LEN
            if ((UINT32)prefix_len > node->prefix_length) {
                prefix_len = node->prefix_length;
            }

            // If there is no match, search is terminated
            if (!prefix_len) {
                return 0;

                // If we've matched the prefix, iterate on this node
            }
            else if (depth + prefix_len == key_length) {
                return recursive_iter(node, callback, data);
            }

            // if there is a full match, go deeper
            depth = depth + node->prefix_length;
        }

        // Recursively search
        child = find_child(node, key[depth]);
        node = (child) ? *child : NULL;
        depth++;
    }
    return 0;
}