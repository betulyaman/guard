#include "adaptive_radix_tree.h"

#include "log.h"

#if DEBUG
#include "test_art.h"
#endif

#ifndef ART_ENABLE_POISON_ON_FREE
#  ifdef DEBUG
#    define ART_ENABLE_POISON_ON_FREE 1
#  else
#    define ART_ENABLE_POISON_ON_FREE 0
#  endif
#endif

ART_TREE g_art_tree;


#pragma warning(push)
#pragma warning(disable: 6101)
STATIC INLINE PUCHAR unicode_to_utf8(_In_ PCUNICODE_STRING unicode, _Out_ PUSHORT out_length)
{
    // Pre-arg guards: do NOT touch out_length on these paths
    if (!unicode || !out_length || !unicode->Buffer || unicode->Length == 0) {
        return NULL;
    }

    // Basic UNICODE_STRING math guard (still pre-arg; don't touch out_length)
    if (unicode->Length > (MAXUSHORT - sizeof(WCHAR))) {
        LOG_MSG("[ART] unicode_to_utf8: source too long for UNICODE_STRING dest (len=%u)", unicode->Length);
        return NULL;
    }

    // Allocate lowercase copy buffer (+NUL). If this fails, keep out_length unchanged.
    UNICODE_STRING lower_unicode;
    RtlInitEmptyUnicodeString(&lower_unicode, NULL, 0);

    const SIZE_T lower_size = (SIZE_T)unicode->Length + sizeof(WCHAR);
    lower_unicode.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, lower_size, ART_TAG);
    if (!lower_unicode.Buffer) {
        return NULL; // early alloc fail (test 6.2 expects out_length unchanged)
    }

    // From this point on, we have "post-arg" work in progress:
    // any failure must zero the published length.
    *out_length = 0;

    lower_unicode.MaximumLength = (USHORT)lower_size;
    lower_unicode.Length = 0;

    NTSTATUS status = RtlDowncaseUnicodeString(&lower_unicode, unicode, FALSE);
    if (!NT_SUCCESS(status)) {
        ExFreePool2(lower_unicode.Buffer, ART_TAG, NULL, 0);
        return NULL; // post-arg failure: out_length already 0
    }

    // Probe required UTF-8 length
    ULONG required_length = 0;
    status = RtlUnicodeToUTF8N(NULL, 0, &required_length,
        lower_unicode.Buffer, lower_unicode.Length);
    if (!NT_SUCCESS(status) || required_length == 0) {
        ExFreePool2(lower_unicode.Buffer, ART_TAG, NULL, 0);
        return NULL;
    }

    // Enforce limits here (tests expect MAX_KEY_LENGTH checked inside this helper)
    if (required_length > MAX_KEY_LENGTH || required_length > MAXUSHORT) {
        LOG_MSG("unicode_to_utf8: key length %lu exceeds limits (MAX_KEY_LENGTH=%u, MAXUSHORT=%u)",
            required_length, (unsigned)MAX_KEY_LENGTH, (unsigned)MAXUSHORT);
        ExFreePool2(lower_unicode.Buffer, ART_TAG, NULL, 0);
        return NULL;
    }

    // Allocate UTF-8 buffer (+NUL)
    const SIZE_T alloc_size = (SIZE_T)required_length + 1;
    PUCHAR utf8_key = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, ART_TAG);
    if (!utf8_key) {
        ExFreePool2(lower_unicode.Buffer, ART_TAG, NULL, 0);
        return NULL;
    }

    // Convert
    ULONG written_length = 0;
    status = RtlUnicodeToUTF8N((PCHAR)utf8_key, required_length, &written_length,
        lower_unicode.Buffer, lower_unicode.Length);

    ExFreePool2(lower_unicode.Buffer, ART_TAG, NULL, 0);

    // Validate conversion
    if (!NT_SUCCESS(status) || written_length == 0 || written_length > required_length) {
        LOG_MSG("unicode_to_utf8: RtlUnicodeToUTF8N failed (st=0x%x, w=%lu, req=%lu)",
            status, written_length, required_length);
        ExFreePool2(utf8_key, ART_TAG, NULL, 0);
        return NULL;
    }

    // Success: publish length and NUL-terminate
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
        ExFreePool2(key, ART_TAG, NULL, 0);
    }
}

STATIC INLINE VOID free_leaf(_Inout_ ART_LEAF** leaf)
{
    if (leaf && *leaf) {
        USHORT prev = (*leaf)->key_length;

#ifdef DEBUG
        if (prev == LEAF_FREED_MAGIC) {
            LOG_MSG("[ART][WARN] double free attempt for leaf %p\n", *leaf);
            Test_DebugBreak();
        }

        g_last_freed_leaf_keylen_before_free = (*leaf)->key_length;
        (*leaf)->key_length = LEAF_FREED_MAGIC; // poison if enabled
#else
        g_last_freed_leaf_keylen_before_free = prev;
#endif

        LOG_MSG("free_leaf: freeing leaf at %p", *leaf);
        ExFreePool2(*leaf, ART_TAG, NULL, 0);
        *leaf = NULL;
    }
}

// Frees an ART_NODE* and sets the caller's pointer to NULL.
STATIC INLINE VOID free_node(_Inout_ ART_NODE** node)
{
    if (!node || !(*node)) {
        return;
    }

    ART_NODE* n = *node;

    // if accidentally passed a leaf-tagged pointer, detect and route to free_leaf 
    if (IS_LEAF(n)) {
#if DEBUG
        LOG_MSG("[ART][BUG] free_node called with a leaf-tagged pointer %p; routing to free_leaf\n", n);
#endif
        ART_LEAF* lf = LEAF_RAW(n);
        if (lf) {
            free_leaf(&lf);
        }
        *node = NULL;
        return;
    }

#if DEBUG
    // For tests: poison the type field before freeing so observers see 0xFF (255).
    g_last_freed_node_type_before_free = (UCHAR)n->type;
    n->type = (NODE_TYPE)0xFF;
#endif

    LOG_MSG("free_node: freeing node at %p (type: %u)", n, (unsigned)n->type);
    ExFreePool2(n, ART_TAG, NULL, 0);

    *node = NULL;
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
        || leaf->key_length == 0
        || leaf->key_length > MAX_KEY_LENGTH) {
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

        // TODO: Performance improvement: Paralel 16bit comparison(ctz)
        // or binary search(keys[] is sequential)
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
        break;
    }

    return NULL;
}

STATIC NTSTATUS copy_header(_Out_ ART_NODE* dst, _In_  ART_NODE* src)
{
    if (!dst || !src) {
        return STATUS_INVALID_PARAMETER;
    }

#if DEBUG
    if (InterlockedExchange(&g_copy_header_fail_once_flag, 0) != 0) {
        return g_copy_header_fail_status;
    }
#endif


    USHORT plen = src->prefix_length;
    if (plen > (USHORT)sizeof(dst->prefix)) {
        plen = (USHORT)sizeof(dst->prefix);
    }

    dst->prefix_length = plen;
    if (plen) {
        RtlCopyMemory(dst->prefix, src->prefix, plen);
    }

    if (plen < sizeof(dst->prefix)) {
        RtlZeroMemory(dst->prefix + plen, sizeof(dst->prefix) - plen);
    }

    dst->num_of_child = 0;

    return STATUS_SUCCESS;
}

STATIC USHORT check_prefix(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth)
{
    if (!node || !key) {
        return 0;
    }

    if (depth >= key_length) {
        return 0;
    }

    if (key_length > MAX_KEY_LENGTH) {
        return 0;
    }

    if (node->prefix_length == 0) {
        return 0;
    }

    // Compute the first compare window:
    const USHORT stored_cap = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, node->prefix_length);
    const USHORT remaining = (USHORT)(key_length - depth);
    const USHORT first_window = (USHORT)min(stored_cap, remaining);

    if (first_window == 0) {
        return 0;
    }

    const UCHAR* pfx = node->prefix;
    const UCHAR* pkey = key + depth;
    // Compare within the first window.
    for (USHORT i = 0; i < first_window; ++i) {
        if (pfx[i] != pkey[i]) {
            return i; // first mismatch position (relative)
        }
    }

    // Full match across the compared window.
    // NOTE: By design, check_prefix() does NOT compare “extended” bytes beyond
    // MAX_PREFIX_LENGTH using a representative leaf. That extended handling is
    // done by prefix_mismatch(). Here we only report matches up to the stored
    // prefix bytes (capped by remaining key length).
    return first_window;
}

// Unified prefix comparator
// Compares node->prefix against key starting at 'depth'.
// - Returns TRUE: full logical prefix matched (all node->prefix_length bytes).
// - Returns FALSE: mismatch (or key too short for the full prefix).
// In both cases, *matched_out is set to the number of consecutive matching bytes
// within the node's logical prefix (0..min(prefix_length, remaining)).
//
// Notes:
// - Compares the stored header bytes first (up to MAX_PREFIX_LENGTH).
// - For logical prefix bytes beyond MAX_PREFIX_LENGTH, it uses a representative
//   leaf as source of truth (either the provided 'rep_leaf_opt' or lazily via minimum(node)).
// - If a mismatch occurs in the stored window but the representative leaf agrees with
//   the search key at that position, it treats it as a "false mismatch" and continues.
STATIC BOOLEAN prefix_compare(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth, _In_opt_ CONST ART_LEAF* rep_leaf_opt, _Out_ USHORT* matched_out)
{
    if (matched_out) {
        *matched_out = 0;
    }
    if (!node || !key || !matched_out) {
        return FALSE;
    }

    if (node->prefix_length == 0) {
        *matched_out = 0;
        return TRUE; // empty prefix trivially matches
    }

    if (depth > key_length) {
        return FALSE;
    }

    USHORT remaining = (USHORT)(key_length - depth);
    if (remaining == 0) {
        // Key exhausted but prefix not emptycannot match full logical prefix
        return FALSE;
    }

    const USHORT stored_cap = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, node->prefix_length);
    const USHORT first_window = (USHORT)min(stored_cap, remaining);

    const UCHAR* pfx = node->prefix;
    const UCHAR* pkey = key + depth;

    // Optional representative leaf (either provided or lazily fetched)
    const ART_LEAF* leaf = rep_leaf_opt;
    USHORT leaf_remaining = 0;
    if (leaf && depth < leaf->key_length) {
        leaf_remaining = (USHORT)(leaf->key_length - depth);
    }
    else {
        leaf = NULL;
    }

    // Compare stored window; tolerate header drift if the leaf confirms the key byte.
    for (USHORT i = 0; i < first_window; ++i) {
        if (pfx[i] != pkey[i]) {
            if (!leaf && node->prefix_length > 0) {
                leaf = minimum(node);
                if (leaf && depth < leaf->key_length) {
                    leaf_remaining = (USHORT)(leaf->key_length - depth);
                }
                else {
                    leaf = NULL;
                }
            }
            if (leaf && leaf_remaining > i && leaf->key[depth + i] == pkey[i]) {
                continue; // accept as match
            }
            *matched_out = i; // first true mismatch
            return FALSE;
        }
    }

    // If the logical prefix fits in the stored window, we are done.
    if (node->prefix_length <= first_window) {
        *matched_out = node->prefix_length;
        return TRUE; // full logical prefix matched
    }

    // Extended path: logical prefix is longer than stored header.
    // If key is shorter than the logical prefix, cannot be a full match.
    if (remaining < node->prefix_length) {
        // We can still validate as far as the key goes to detect early mismatch.
        USHORT extra_key = (USHORT)(remaining - first_window);
        if (extra_key == 0) {
            *matched_out = first_window;
            return FALSE;
        }
        if (!leaf) {
            leaf = minimum(node);
            if (leaf && depth < leaf->key_length) {
                leaf_remaining = (USHORT)(leaf->key_length - depth);
            }
            else {
                // No way to validate extended bytes; treat as not-full.
                *matched_out = first_window;
                return FALSE;
            }
        }
        USHORT leaf_extra = (leaf_remaining > first_window)
            ? (USHORT)(leaf_remaining - first_window)
            : 0;
        USHORT to_check = min(extra_key, leaf_extra);
        for (USHORT j = 0; j < to_check; ++j) {
            USHORT idx = (USHORT)(first_window + j);
            if (leaf->key[depth + idx] != key[depth + idx]) {
                *matched_out = idx;
                return FALSE;
            }
        }
        // Key ended before completing logical prefixnot a full match
        *matched_out = (USHORT)(first_window + to_check);
        return FALSE;
    }

    // Key is long enough; validate remaining logical prefix bytes using the leaf.
    if (!leaf) {
        leaf = minimum(node);
        if (leaf && depth < leaf->key_length) {
            leaf_remaining = (USHORT)(leaf->key_length - depth);
        }
        else {
            // Cannot validate extended bytes; report stored bytes only.
            *matched_out = first_window;
            return FALSE;
        }
    }

    USHORT logical_extra = (USHORT)(node->prefix_length - first_window);
    USHORT leaf_extra = (leaf_remaining > first_window)
        ? (USHORT)(leaf_remaining - first_window)
        : 0;
    USHORT to_check = min(logical_extra, leaf_extra);

    for (USHORT j = 0; j < to_check; ++j) {
        USHORT idx = (USHORT)(first_window + j);
        if (leaf->key[depth + idx] != key[depth + idx]) {
            *matched_out = idx;
            return FALSE;
        }
    }

    if (to_check < logical_extra) {
        // Not enough bytes available in representative leafconservatively not full
        *matched_out = (USHORT)(first_window + to_check);
        return FALSE;
    }

    // Full logical prefix matched
    *matched_out = node->prefix_length;
    return TRUE;
}

/** INSERT Functions */

STATIC ART_LEAF* minimum(CONST ART_NODE* node)
{
    if (!node) {
        return NULL;
    }

    // Caller might pass a leaf-encoded pointer by mistake.
    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    if (node->type < NODE4 || node->type > NODE256) {
        LOG_MSG("minimum: invalid node type %d", node->type);
        return NULL;
    }
    if (node->num_of_child == 0) {
        LOG_MSG("minimum: node has no children");
        return NULL;
    }

    switch (node->type) {

    case NODE4: {
        // Fast path: children are kept sorted and densely packed in [0..num_of_child-1]
        const ART_NODE4* n = (const ART_NODE4*)node;
        USHORT limit = (USHORT)min(n->base.num_of_child, 4);
        for (USHORT i = 0; i < limit; ++i) {
            ART_NODE* ch = n->children[i];
            if (!ch) {
                LOG_MSG("minimum: NULL child in NODE4 at %u (count=%u)", i, limit);
                continue; // be tolerant in DEBUG/testing scenarios
            }
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = minimum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE16: {
        // Same idea as NODE4, but up to 16 entries
        const ART_NODE16* n = (const ART_NODE16*)node;
        USHORT limit = (USHORT)min(n->base.num_of_child, 16);
        for (USHORT i = 0; i < limit; ++i) {
            ART_NODE* ch = n->children[i];
            if (!ch) {
                LOG_MSG("minimum: NULL child in NODE16 at %u (count=%u)", i, limit);
                continue;
            }
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = minimum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE48: {
        // child_index[k] = 1..48children[map-1]
        const ART_NODE48* n = (const ART_NODE48*)node;
        for (int k = 0; k < 256; ++k) {
            UCHAR map = n->child_index[k];
            if (map == 0) continue;

            int idx = (int)map - 1;
            if (idx < 0 || idx >= 48) {
                LOG_MSG("minimum: corrupt index in NODE48 (map=%u for key=%d)", map, k);
                return NULL; // fail fast on structural corruption
            }
            ART_NODE* ch = n->children[idx];
            if (!ch) {
                LOG_MSG("minimum: mapped NULL child in NODE48 (key=%d, idx=%d)", k, idx);
                return NULL; // fail fast — tests expect this
            }
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = minimum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE256: {
        // Direct table; smallest non-NULL index is the minimum.
        const ART_NODE256* n = (const ART_NODE256*)node;
        for (int k = 0; k < 256; ++k) {
            ART_NODE* ch = n->children[k];
            if (!ch) continue;
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = minimum(ch);
            if (lf) return lf;
        }
        break;
    }

    default:
        LOG_MSG("minimum: unexpected node type %d", node->type);
        return NULL;
    }

    LOG_MSG("minimum: no valid child found while descending");
    return NULL;
}
STATIC ART_LEAF* maximum(CONST ART_NODE* node)
{
    if (!node) return NULL;

    if (IS_LEAF(node)) {
        return LEAF_RAW(node);
    }

    if (node->type < NODE4 || node->type > NODE256) {
        LOG_MSG("maximum: invalid node type %d", node->type);
        return NULL;
    }
    if (node->num_of_child == 0) {
        LOG_MSG("maximum: node has no children");
        return NULL;
    }

    switch (node->type) {

    case NODE4: {
        const ART_NODE4* n = (const ART_NODE4*)node;
        USHORT limit = (USHORT)min(n->base.num_of_child, 4);
        for (int i = (int)limit - 1; i >= 0; --i) {
            ART_NODE* ch = n->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = maximum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE16: {
        const ART_NODE16* n = (const ART_NODE16*)node;
        USHORT limit = (USHORT)min(n->base.num_of_child, 16);
        for (int i = (int)limit - 1; i >= 0; --i) {
            ART_NODE* ch = n->children[i];
            if (!ch) continue;
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = maximum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE48: {
        const ART_NODE48* n = (const ART_NODE48*)node;
        // Scan keyspace high → low; skip unmapped and mapped-but-NULL entries.
        for (int k = 255; k >= 0; --k) {
            UCHAR map = n->child_index[k];   // 1..48; 0 = unmapped
            if (map == 0) continue;

            int idx = (int)map - 1;
            if (idx < 0 || idx >= 48) {
                LOG_MSG("maximum: corrupt NODE48 index (map=%u for key=%d)", map, k);
                continue; // be tolerant: skip corrupt slot instead of aborting
            }

            ART_NODE* ch = n->children[idx];
            if (!ch) {
                // do not fail fast; just skip to the next lower mapping.
                LOG_MSG("maximum: mapped NULL child in NODE48 (key=%d, idx=%d) — skipping", k, idx);
                continue;
            }

            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = maximum(ch);
            if (lf) return lf;
        }
        break;
    }

    case NODE256: {
        const ART_NODE256* n = (const ART_NODE256*)node;
        for (int k = 255; k >= 0; --k) {
            ART_NODE* ch = n->children[k];
            if (!ch) continue;
            if (IS_LEAF(ch)) return LEAF_RAW(ch);
            ART_LEAF* lf = maximum(ch);
            if (lf) return lf;
        }
        break;
    }

    default:
        LOG_MSG("maximum: unexpected node type %d", node->type);
        return NULL;
    }

    LOG_MSG("maximum: no valid child found while descending");
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

STATIC ART_LEAF* make_leaf(CONST PUCHAR key, USHORT key_length, ULONG value)
{
    if ((!key && key_length)) {
        return NULL;
    }

    if (key_length > MAX_KEY_LENGTH) {
        return NULL;
    }

    SIZE_T base = FIELD_OFFSET(ART_LEAF, key);
    // overflow guard: alloc_size + key_length must fit into SIZE_T
    if (key_length > (SIZE_T_MAX - base)) {
        return NULL;
    }
    SIZE_T alloc_size = base + key_length;
    ART_LEAF* leaf = (ART_LEAF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, ART_TAG);
    if (!leaf) {
        LOG_MSG("make_leaf: Memory allocation failed");
        return NULL;
    }

    RtlZeroMemory(leaf, alloc_size);
    leaf->value = value;
    leaf->key_length = (USHORT)key_length;
    if (key_length && key) {
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

    if (depth >= leaf1->key_length || depth >= leaf2->key_length) {
        return 0;  // No common prefix when depth reaches or exceeds key length
    }

    USHORT min_remaining_length = min(leaf1->key_length - depth, leaf2->key_length - depth);

    // Bounds checking to prevent buffer overrun
    for (USHORT index = 0; index < min_remaining_length; index++) {
        USHORT pos1 = depth + index;

        if (pos1 >= leaf1->key_length || pos1 >= leaf2->key_length) {
            break;
        }

        if (leaf1->key[pos1] != leaf2->key[pos1]) {
            return index;
        }
    }

    return min_remaining_length;
}

STATIC USHORT prefix_mismatch(_In_ CONST ART_NODE* node,_In_reads_bytes_(key_length) CONST PUCHAR key,_In_ USHORT key_length,_In_ USHORT depth,_In_opt_ CONST ART_LEAF* rep_leaf)
{
    if (!node || !key) {
        LOG_MSG("prefix_mismatch: NULL parameter");
        return 0;
    }
    if (depth > key_length) {
        LOG_MSG("prefix_mismatch: depth %u > key_length %u", depth, key_length);
        return 0;
    }
    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("prefix_mismatch: key_length %u > MAX_KEY_LENGTH", key_length);
        return 0;
    }

    USHORT remaining = (USHORT)(key_length - depth);
    if (remaining == 0) {
        return 0;
    }

    // Compare the stored (possibly truncated) block first.
    const USHORT stored_cap = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, node->prefix_length);
    const USHORT first_window = (USHORT)min(stored_cap, remaining);

    // Use the provided representative leaf if any; otherwise we may fetch it lazily below
    const ART_LEAF* leaf = rep_leaf;
    USHORT leaf_remaining = 0;
    if (leaf && depth < leaf->key_length) {
        leaf_remaining = (USHORT)(leaf->key_length - depth);
    }
    else {
        leaf = NULL; // temsilci yaprak kullanılamıyorsa NULL’a çek
    }

    // Stored window compare with optional cross-check against the representative leaf.
    // If a mismatch against node->prefix[] occurs at i, treat it as a "false mismatch"
    // and continue when the representative leaf agrees with the search key at that position.
    for (USHORT i = 0; i < first_window; ++i) {
        UCHAR p = node->prefix[i];
        UCHAR k = key[depth + i];

        if (p != k) {
            // Lazily obtain a representative leaf if not provided but needed for cross-check
            if (!leaf && node->prefix_length > 0) {
                leaf = minimum(node);
                if (leaf && depth < leaf->key_length) {
                    leaf_remaining = (USHORT)(leaf->key_length - depth);
                }
                else {
                    leaf = NULL;
                }
            }

            if (leaf && leaf_remaining > i && leaf->key[depth + i] == k) {
                continue; // accept as match; stored byte may be stale/truncated
            }
            return i; // true mismatch at i
        }
    }

    // If the node's logical prefix fits entirely in the stored window, we are done.
    if (node->prefix_length <= first_window) {
        return first_window;
    }

    // Extended path: stored window matched, but logical prefix is longer.
    // We need a representative leaf to validate bytes beyond MAX_PREFIX_LENGTH.
    if (!leaf) {
        leaf = minimum(node);
        if (leaf && depth < leaf->key_length) {
            leaf_remaining = (USHORT)(leaf->key_length - depth);
        }
        else {
            LOG_MSG("prefix_mismatch: No leaf available for extended prefix check");
            return first_window;
        }
    }

    USHORT logical_extra = (USHORT)(node->prefix_length - first_window);
    USHORT key_extra = (remaining > first_window) ? (USHORT)(remaining - first_window) : 0;
    USHORT leaf_extra = (leaf_remaining > first_window) ? (USHORT)(leaf_remaining - first_window) : 0;

    USHORT extra_limit = logical_extra;
    if (key_extra < extra_limit) extra_limit = key_extra;
    if (leaf_extra < extra_limit) extra_limit = leaf_extra;

    // Compare the extended region sourced from the leaf's key.
    for (USHORT j = 0; j < extra_limit; ++j) {
        USHORT idx = (USHORT)(first_window + j);
        if (leaf->key[depth + idx] != key[depth + idx]) {
            return idx; // first mismatch in extended area
        }
    }

    return (USHORT)(first_window + extra_limit); // full match across requested window
}

STATIC NTSTATUS add_child256(_Inout_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child)
{
    UNREFERENCED_PARAMETER(ref);

    if (!node || !child) {
        LOG_MSG("add_child256: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE256) {
        LOG_MSG("add_child256: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    // 1) Full capacity reject (no side effects).
    if (node->base.num_of_child >= 256) {
        LOG_MSG("add_child256: Node full, cannot add more children");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 2) Slot collision reject (no side effects).
    if (node->children[c] != NULL) {
        LOG_MSG("add_child256: Key byte %u already occupied", (unsigned)c);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    // 3) Perform the insertion only after all checks pass.
    node->children[c] = (ART_NODE*)child;
    node->base.num_of_child++;

#if DEBUG
    // Sanity check: still within bounds.
    if (node->base.num_of_child == 0 || node->base.num_of_child > 256) {
        LOG_MSG("add_child256: child count out of range (%u)", node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }
#endif
    return STATUS_SUCCESS;
}

STATIC NTSTATUS add_child48(_Inout_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child)
{
#if DEBUG
    if (g_mock_add_child48_once != STATUS_SUCCESS) {
        NTSTATUS once = g_mock_add_child48_once;
        g_mock_add_child48_once = STATUS_SUCCESS;
        LOG_MSG("add_child48: (mock) forcing failure 0x%x", once);
        return once;
    }
#endif

    if (!node || !ref || !child) {
        LOG_MSG("add_child48: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE48) {
        LOG_MSG("add_child48: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    // Fast path: still room in NODE48
    if (node->base.num_of_child < 48) {
        // Here, collision should be detected immediately (no expansion)
        if (node->child_index[c] != 0) {
            LOG_MSG("add_child48: Key %u already exists (no expand)", c);
            return STATUS_OBJECT_NAME_COLLISION;
        }

        // Find first free slot
        UINT8 pos = 0;
        while (pos < 48 && node->children[pos] != NULL) pos++;
        if (pos >= 48) {
            LOG_MSG("add_child48: Inconsistent state - no free slots but count < 48");
            return STATUS_INTERNAL_ERROR;
        }

        node->children[pos] = (ART_NODE*)child;
        node->child_index[c] = (UCHAR)(pos + 1);   // map 1..48 (0 = empty)
        node->base.num_of_child++;
        return STATUS_SUCCESS;
    }

    // Slow path: node is FULL -> expand to NODE256 first (even if c already exists).
    ART_NODE256* new_node = (ART_NODE256*)art_create_node(NODE256);
    if (!new_node) {
        LOG_MSG("add_child48: Failed to create NODE256");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
    if (!NT_SUCCESS(status)) {
        LOG_MSG("add_child48: Failed to copy header");
        free_node((ART_NODE**)&new_node);
        return status;
    }

    // Repack existing children into the 256-way table
    RtlZeroMemory(new_node->children, sizeof(new_node->children));
    USHORT moved = 0;
    for (UINT16 k = 0; k < 256; ++k) {
        UCHAR map = node->child_index[k];         // 1..48 or 0
        if (map == 0) continue;

        UINT8 idx = (UINT8)(map - 1);
        if (idx >= 48) {
            LOG_MSG("add_child48: Invalid child index %u for key %u", idx, k);
            free_node((ART_NODE**)&new_node);
            return STATUS_DATA_ERROR;
        }

        ART_NODE* ch = node->children[idx];
        if (!ch) {
            LOG_MSG("add_child48: Mapped NULL child for key %u (idx=%u)", k, idx);
            free_node((ART_NODE**)&new_node);
            return STATUS_DATA_ERROR;
        }

        new_node->children[k] = ch;
        moved++;
    }
    new_node->base.num_of_child = moved;

    // Try to add the new edge in the expanded node
    ART_NODE* tmp_ref = (ART_NODE*)new_node; // not publishing yet
    status = add_child256(new_node, &tmp_ref, c, child);
    if (!NT_SUCCESS(status)) {
        // free the temporary NODE256 on failure (collision, etc.)
        LOG_MSG("add_child48: Failed to add child to new NODE256 (st=0x%x)", status);
        free_node((ART_NODE**)&new_node);
        return status;
    }

    // Success: publish and free old NODE48 (children are re-used)
    ART_NODE* old_node = (ART_NODE*)node;
    *ref = (ART_NODE*)new_node;
    free_node(&old_node);
    return STATUS_SUCCESS;
}

STATIC NTSTATUS add_child16(_Inout_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child)
{
    if (!node || !ref || !child) {
        LOG_MSG("add_child16: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE16) {
        LOG_MSG("add_child16: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

#if DEBUG
    if (*ref != (ART_NODE*)node) {
        LOG_MSG("[ART][BUG] add_child16: *ref (%p) != node (%p)", *ref, node);
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.num_of_child == 0 || node->base.num_of_child > 16) {
        LOG_MSG("[ART] add_child16: corrupt child count %u", node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }
#endif

    // Fast in-place path while there is room (0..15 -> insert as 16th).
    if (node->base.num_of_child < 16) {
        // Duplicate check (fast path): no side effects on collision.
        for (USHORT i = 0; i < node->base.num_of_child; ++i) {
            if (node->keys[i] == c) {
                LOG_MSG("add_child16: Duplicate key %u (fast path)", (unsigned)c);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }

        // Sorted insert (stable).
        USHORT pos = node->base.num_of_child;
        while (pos > 0 && node->keys[pos - 1] > c) {
            node->keys[pos] = node->keys[pos - 1];
            node->children[pos] = node->children[pos - 1];
            pos--;
        }
        node->keys[pos] = c;
        node->children[pos] = (ART_NODE*)child;
        node->base.num_of_child++;
        return STATUS_SUCCESS;
    }

    // Node is full (16/16). Check duplicate before any allocation/expansion.
    for (USHORT i = 0; i < 16; ++i) {
        if (node->keys[i] == c) {
            LOG_MSG("add_child16: Duplicate key %u on full node (short-circuit, no expand)", (unsigned)c);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    // Expand to NODE48. No mutation to the original node until publish succeeds.
    ART_NODE48* new48 = (ART_NODE48*)art_create_node(NODE48);
    if (!new48) {
        LOG_MSG("add_child16: Failed to create NODE48");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy header into the temporary NODE48. On failure, free temp and bubble the status.
    NTSTATUS st = copy_header((ART_NODE*)new48, (ART_NODE*)node);
    if (!NT_SUCCESS(st)) {
        LOG_MSG("add_child16: copy_header failed (st=0x%x)", st);
        free_node((ART_NODE**)&new48); // temp only; original node untouched
        return st;                     // bubble exact status (e.g., STATUS_DATA_ERROR)
    }

    // Prepare NODE48 fields.
    RtlZeroMemory(new48->child_index, sizeof new48->child_index);
    RtlZeroMemory(new48->children, sizeof new48->children);
    new48->base.num_of_child = 0;

    // Use a sink so add_child48 can't overwrite new48 via *ref.
    ART_NODE* sink = (ART_NODE*)new48;

    // Repack existing 16 entries into NODE48.
    for (USHORT i = 0; i < 16; ++i) {
        if (!node->children[i]) {
            LOG_MSG("add_child16: NULL child at %u during repack", i);
            free_node((ART_NODE**)&new48);
            return STATUS_DATA_ERROR;
        }
        UCHAR k = node->keys[i];

        // Defensive: ensure no duplicates among the 16; add_child48 would also detect,
        // but we keep an early check to maintain clearer error reporting.
        if (new48->child_index[k] != 0) {
            LOG_MSG("add_child16: duplicate key in repack (%u)", (unsigned)k);
            free_node((ART_NODE**)&new48);
            return STATUS_DATA_ERROR;
        }

        st = add_child48(new48, &sink, k, node->children[i]);
        if (!NT_SUCCESS(st)) {
            LOG_MSG("add_child16: add_child48 (repack) failed (st=0x%x)", st);
            free_node((ART_NODE**)&new48);
            return st;
        }
    }

    // Insert the new child into the freshly built NODE48.
    sink = (ART_NODE*)new48; // refresh sink (defense-in-depth)
    st = add_child48(new48, &sink, c, child);
    if (!NT_SUCCESS(st)) {
        LOG_MSG("add_child16: add_child48 failed (st=0x%x)", st);
        free_node((ART_NODE**)&new48);
        return st;
    }

    // Success: publish the upgraded node and free the old NODE16.
    *ref = (ART_NODE*)new48;
    free_node((ART_NODE**)&node);
    return STATUS_SUCCESS;
}

#ifndef ART_STRICT_NODE4_VERIFY
#define ART_STRICT_NODE4_VERIFY 0 // 1: returns DATA_ERROR when NODE4->num_of_child > 4
#endif

STATIC NTSTATUS add_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child)
{
    if (!node || !ref || !child) {
        LOG_MSG("add_child4: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (node->base.type != NODE4) {
        LOG_MSG("add_child4: Invalid node type %d", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }

    // Reject duplicate key
    for (USHORT i = 0; i < node->base.num_of_child && i < 4; i++) {
        if (node->keys[i] == c) {
            LOG_MSG("add_child4: Duplicate key %d", c);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    // Fast path: room available in NODE4, do a sorted insert
    if (node->base.num_of_child < 4) {
        USHORT idx = 0;
        while (idx < node->base.num_of_child && node->keys[idx] < c) {
            idx++;
        }

        if (idx >= 4 || node->base.num_of_child >= 4) {
            LOG_MSG("add_child4: Invalid insertion index %u", idx);
            return STATUS_INTERNAL_ERROR;
        }

        // Make room (overlapping ranges -> RtlMoveMemory)
        if (idx < node->base.num_of_child) {
            SIZE_T move = (SIZE_T)(node->base.num_of_child - idx);
            if (idx + move >= 4) {
                LOG_MSG("add_child4: shift would overflow array (idx=%u, move=%Iu)", idx, move);
                return STATUS_INTERNAL_ERROR;
            }
            if (move > 0) {
                RtlMoveMemory(&node->keys[idx + 1], &node->keys[idx], move * sizeof(UCHAR));
                RtlMoveMemory(&node->children[idx + 1], &node->children[idx], move * sizeof(PVOID));
            }
        }

        node->keys[idx] = c;
        node->children[idx] = (ART_NODE*)child;
        node->base.num_of_child++;
        return STATUS_SUCCESS;
    }

    // Slow path: expand NODE4 -> NODE16, preserving existing key layout in [0..3]
    ART_NODE16* new_node = (ART_NODE16*)art_create_node(NODE16);
    if (!new_node) {
        LOG_MSG("add_child4: Failed to create NODE16");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy header (num_of_child, prefix_length, prefix) but keep new_node->type = NODE16
    NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
    if (!NT_SUCCESS(status)) {
        LOG_MSG("add_child4: Failed to copy header");
        free_node((ART_NODE**)&new_node);
        return status;
    }

    // Defensive: clamp or fail if corrupted count
    USHORT copy_cnt = node->base.num_of_child;
#if ART_STRICT_NODE4_VERIFY
    if (copy_cnt > 4) {
        LOG_MSG("add_child4: corrupted child count (%u) for NODE4", copy_cnt);
        free_node((ART_NODE**)&new_node);
        return STATUS_DATA_ERROR;
    }
#else
    if (copy_cnt > 4) copy_cnt = 4;
#endif

    // Initialize destination arrays then copy survivors verbatim to slots [0..copy_cnt-1]
    RtlZeroMemory(new_node->children, sizeof new_node->children);
    RtlZeroMemory(new_node->keys, sizeof new_node->keys);
    if (copy_cnt) {
        RtlCopyMemory(new_node->children, node->children, copy_cnt * sizeof(PVOID));
        RtlCopyMemory(new_node->keys, node->keys, copy_cnt * sizeof(UCHAR));
    }
    new_node->base.num_of_child = copy_cnt; // typically 4

    // Append the new (c, child) at the next free slot to preserve original [0..3] layout
    if (new_node->base.num_of_child >= 16) {
        LOG_MSG("add_child4: new NODE16 unexpectedly full");
        free_node((ART_NODE**)&new_node);
        return STATUS_INTERNAL_ERROR;
    }
    new_node->keys[new_node->base.num_of_child] = c;
    new_node->children[new_node->base.num_of_child] = (ART_NODE*)child;
    new_node->base.num_of_child++;

    // Publish and free old node
    ART_NODE* old_node = (ART_NODE*)node;
    *ref = (ART_NODE*)new_node;
    free_node(&old_node);
    return STATUS_SUCCESS;
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

STATIC NTSTATUS recursive_insert(
    _Inout_opt_ ART_NODE* node,
    _Inout_ ART_NODE** ref,
    _In_ CONST PUCHAR key,
    _In_ USHORT key_length,
    _In_ ULONG value,
    _In_ USHORT depth,
    _Out_ PBOOLEAN old,
    _In_ BOOLEAN replace,
    _Out_ PULONG old_value)
{
    NTSTATUS  status = STATUS_SUCCESS;

    // scratch allocations that must be freed on error paths
    ART_LEAF* new_leaf = NULL;   // generic new leaf
    ART_LEAF* term_leaf = NULL;   // leaf for terminator edge
    ART_NODE4* new_node4 = NULL;   // parent created during leaf/prefix split
    ART_NODE* tmp_ref = NULL;   // transient parent that may expand (4→16)

    if (!ref || !key || !old || !old_value) {
        LOG_MSG("recursive_insert: NULL parameters");
        status = STATUS_INVALID_PARAMETER;
        goto CLEANUP;
    }
    if (depth > key_length) {
        LOG_MSG("recursive_insert: Depth %u exceeds key length %u", depth, key_length);
        status = STATUS_INVALID_PARAMETER;
        goto CLEANUP;
    }
    // NEW: overly long key is a caller error (avoid mis-reporting as alloc fail)
#if defined(MAX_KEY_LENGTH)
    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("recursive_insert: key_length %u > MAX_KEY_LENGTH %u", key_length, (USHORT)MAX_KEY_LENGTH);
        status = STATUS_INVALID_PARAMETER;
        goto CLEANUP;
    }
#endif

    * old = FALSE;
    *old_value = POLICY_NONE;

    // (1) Empty slotcreate and publish a leaf
    if (!node) {
        new_leaf = make_leaf(key, key_length, value);
        if (!new_leaf) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto CLEANUP;
        }
        *ref = (ART_NODE*)SET_LEAF(new_leaf);
        new_leaf = NULL; // published
        goto CLEANUP;    // success
    }

    // NEW: sanity for internal nodes (type / capacity)
    if (!IS_LEAF(node)) {
        USHORT cap = 0;
        switch (node->type) {
        case NODE4:   cap = 4;  break;
        case NODE16:  cap = 16; break;
        case NODE48:  cap = 48; break;
        case NODE256: cap = 256; break;
        default:
            LOG_MSG("recursive_insert: invalid node type %d", node->type);
            status = STATUS_INVALID_PARAMETER;
            goto CLEANUP;
        }
        if (node->num_of_child > cap) {
            LOG_MSG("recursive_insert: corrupt child count %u for type %d (cap=%u)",
                node->num_of_child, node->type, cap);
            status = STATUS_DATA_ERROR;
            goto CLEANUP;
        }
    }

    // (2) Leafupdate or split
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            status = STATUS_DATA_ERROR;
            goto CLEANUP;
        }

        if (leaf_matches(leaf, key, (SIZE_T)key_length)) {
            *old = TRUE;
            *old_value = leaf->value;
            if (replace) {
                leaf->value = value;
            }
            goto CLEANUP; // success
        }

        // Split this leaf and create a new parent (NODE4)
        new_node4 = (ART_NODE4*)art_create_node(NODE4);
        if (!new_node4) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto CLEANUP;
        }

        new_leaf = make_leaf(key, key_length, value);
        if (!new_leaf) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto CLEANUP;
        }

        USHORT lcp = longest_common_prefix(leaf, new_leaf, depth);
        USHORT rem_old = (leaf->key_length > depth) ? (USHORT)(leaf->key_length - depth) : 0;
        USHORT rem_new = (new_leaf->key_length > depth) ? (USHORT)(new_leaf->key_length - depth) : 0;
        USHORT max_remaining = min(rem_old, rem_new);
        if (lcp > max_remaining) {
            status = STATUS_DATA_ERROR;
            goto CLEANUP;
        }

        new_node4->base.prefix_length = lcp;
        if (lcp) {
            SIZE_T copy = min((SIZE_T)MAX_PREFIX_LENGTH, (SIZE_T)lcp);
            if ((USHORT)(depth + copy) < depth) { status = STATUS_INTEGER_OVERFLOW; goto CLEANUP; }
            if (depth + copy > key_length) copy = key_length - depth;
            if (copy) RtlCopyMemory(new_node4->base.prefix, key + depth, copy);
            if (copy < MAX_PREFIX_LENGTH)
                RtlZeroMemory(new_node4->base.prefix + copy, MAX_PREFIX_LENGTH - copy);
        }
        else {
            RtlZeroMemory(new_node4->base.prefix, MAX_PREFIX_LENGTH);
        }

        USHORT split_depth = (USHORT)(depth + lcp);
        UCHAR old_edge = (split_depth < leaf->key_length) ? leaf->key[split_depth] : 0;
        UCHAR new_edge = (split_depth < new_leaf->key_length) ? new_leaf->key[split_depth] : 0;
        if (old_edge == new_edge) { // would mean keys identical up to terminator, but matched above handled duplicates
            status = STATUS_DATA_ERROR;
            goto CLEANUP;
        }

        // Attach OLD leaf under new parent
        tmp_ref = (ART_NODE*)new_node4;
        status = add_child4(new_node4, &tmp_ref, old_edge, SET_LEAF(leaf));
        if (!NT_SUCCESS(status)) {
            goto CLEANUP;
        }

        // Attach NEW leaf (tmp_ref may have expanded to NODE16)
        status = add_child(tmp_ref, &tmp_ref, new_edge, SET_LEAF(new_leaf));
        if (!NT_SUCCESS(status)) {
            // tmp_ref holds the newly built subtree; free it here and clear tracking.
            free_node(&tmp_ref);
            new_node4 = NULL; // already freed via tmp_ref
            // new_leaf not publishedlet CLEANUP free it
            goto CLEANUP;
        }

        // Publish and clear scratch ownership
        *ref = tmp_ref;
        tmp_ref = NULL;     // published
        new_node4 = NULL;   // owned by tree (may be 4 or 16 now)
        new_leaf = NULL;    // published via add_child
        goto CLEANUP;       // success
    }

    // (3) Internal node: compressed prefix handling (prefix_compare handles long prefixes)
    if (node->prefix_length > 0) {
        USHORT matched = 0;
        BOOLEAN full = prefix_compare(node, key, key_length, depth, NULL, &matched);

        if (full) {
            // Entire logical prefix matched
            if ((USHORT)(depth + node->prefix_length) < depth) {
                status = STATUS_INTEGER_OVERFLOW;
                goto CLEANUP;
            }
            depth += node->prefix_length;

            if (depth == key_length) {
                ART_NODE** term = find_child(node, 0);
                if (term && *term) {
                    if (!IS_LEAF(*term)) {
                        status = STATUS_DATA_ERROR;
                        goto CLEANUP;
                    }
                    ART_LEAF* t = LEAF_RAW(*term);
                    if (!t) {
                        status = STATUS_DATA_ERROR;
                        goto CLEANUP;
                    }
                    *old = TRUE;
                    *old_value = t->value;
                    if (replace) t->value = value;
                    goto CLEANUP; // success
                }
                else {
                    term_leaf = make_leaf(key, key_length, value);
                    if (!term_leaf) {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        goto CLEANUP;
                    }
                    status = add_child(node, ref, 0, SET_LEAF(term_leaf));
                    if (!NT_SUCCESS(status)) {
                        goto CLEANUP; // term_leaf freed below
                    }
                    term_leaf = NULL; // published
                    goto CLEANUP;     // success
                }
            }
            // fallthrough to RECURSE_SEARCH
        }
        else {
            // Split current node’s prefix at 'matched'
            new_node4 = (ART_NODE4*)art_create_node(NODE4);
            if (!new_node4) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CLEANUP;
            }

            new_node4->base.prefix_length = matched;
            if (matched) {
                USHORT copy_len = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, matched);
                RtlCopyMemory(new_node4->base.prefix, node->prefix, copy_len);
                if (copy_len < MAX_PREFIX_LENGTH)
                    RtlZeroMemory(new_node4->base.prefix + copy_len, MAX_PREFIX_LENGTH - copy_len);
            }
            else {
                RtlZeroMemory(new_node4->base.prefix, MAX_PREFIX_LENGTH);
            }

            // Diverging byte for OLD branch
            UCHAR old_key_byte = 0;
            if (node->prefix_length <= MAX_PREFIX_LENGTH) {
                if (matched >= node->prefix_length) {
                    status = STATUS_DATA_ERROR;
                    goto CLEANUP;
                }
                old_key_byte = node->prefix[matched];
            }
            else {
                const ART_LEAF* rep = minimum(node);
                if (!rep || (USHORT)(depth + matched) >= rep->key_length) {
                    status = STATUS_DATA_ERROR;
                    goto CLEANUP;
                }
                old_key_byte = rep->key[depth + matched];
            }

            // Shorten OLD node’s stored prefix by (matched + 1)
            USHORT new_prefix_length = 0;
            if (node->prefix_length > (USHORT)(matched + 1))
                new_prefix_length = (USHORT)(node->prefix_length - (matched + 1));

            if (node->prefix_length <= MAX_PREFIX_LENGTH) {
                USHORT stored = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, new_prefix_length);
                if (stored) {
                    RtlMoveMemory(node->prefix, &node->prefix[matched + 1], stored);
                }
                if (stored < MAX_PREFIX_LENGTH) {
                    RtlZeroMemory(node->prefix + stored, MAX_PREFIX_LENGTH - stored);
                }
            }
            else {
                const ART_LEAF* rep = minimum(node);
                if (rep) {
                    USHORT can_copy = 0;
                    if ((USHORT)(depth + matched + 1) < rep->key_length) {
                        SIZE_T avail = rep->key_length - (SIZE_T)(depth + matched + 1);
                        can_copy = (USHORT)min((SIZE_T)MAX_PREFIX_LENGTH, avail);
                    }
                    if (can_copy) {
                        RtlCopyMemory(node->prefix, &rep->key[depth + matched + 1], can_copy);
                    }
                    if (can_copy < MAX_PREFIX_LENGTH) {
                        RtlZeroMemory(node->prefix + can_copy, MAX_PREFIX_LENGTH - can_copy);
                    }
                }
                else {
                    RtlZeroMemory(node->prefix, MAX_PREFIX_LENGTH);
                }
            }
            node->prefix_length = new_prefix_length;

            // Build new parent and attach both branches
            tmp_ref = (ART_NODE*)new_node4;

            status = add_child4(new_node4, &tmp_ref, old_key_byte, node);
            if (!NT_SUCCESS(status)) {
                goto CLEANUP;
            }

            new_leaf = make_leaf(key, key_length, value);
            if (!new_leaf) {
                // tmp_ref subtree exists; free it and null tracking
                free_node(&tmp_ref);
                new_node4 = NULL;
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CLEANUP;
            }

            if ((USHORT)(depth + matched) < depth) { status = STATUS_INTEGER_OVERFLOW; goto CLEANUP; }
            UCHAR new_edge = (((USHORT)(depth + matched)) < key_length) ? key[depth + matched] : 0;
            if (new_edge == old_key_byte) {
                free_node(&tmp_ref); // free built subtree
                new_node4 = NULL;
                status = STATUS_DATA_ERROR;
                goto CLEANUP;
            }

            status = add_child(tmp_ref, &tmp_ref, new_edge, SET_LEAF(new_leaf));
            if (!NT_SUCCESS(status)) {
                free_node(&tmp_ref); // free built subtree
                new_node4 = NULL;
                goto CLEANUP; // new_leaf freed below
            }

            // Publish
            *ref = tmp_ref;
            tmp_ref = NULL;
            new_node4 = NULL;
            new_leaf = NULL; // published
            goto CLEANUP;     // success
        }
    }

    // ===== RECURSE_SEARCH =====
    if (depth == key_length) {
        ART_NODE** term = find_child(node, 0);
        if (term && *term) {
            if (!IS_LEAF(*term)) {
                status = STATUS_DATA_ERROR;
                goto CLEANUP;
            }
            ART_LEAF* t = LEAF_RAW(*term);
            if (!t) {
                status = STATUS_DATA_ERROR;
                goto CLEANUP;
            }
            *old = TRUE;
            *old_value = t->value;
            if (replace) t->value = value;
            goto CLEANUP; // success
        }
        else {
            term_leaf = make_leaf(key, key_length, value);
            if (!term_leaf) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CLEANUP;
            }
            status = add_child(node, ref, 0, SET_LEAF(term_leaf));
            if (!NT_SUCCESS(status)) {
                goto CLEANUP; // term_leaf freed below
            }
            term_leaf = NULL; // published
            goto CLEANUP;     // success
        }
    }

    {
        ART_NODE** child = find_child(node, key[depth]);
        if (child && *child) {
            status = recursive_insert(*child, child, key, key_length, value,
                (USHORT)(depth + 1), old, replace, old_value);
            goto CLEANUP;
        }
    }

    // Create a new leaf on the next edge
    new_leaf = make_leaf(key, key_length, value);
    if (!new_leaf) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CLEANUP;
    }
    status = add_child(node, ref, key[depth], SET_LEAF(new_leaf));
    if (!NT_SUCCESS(status)) {
        goto CLEANUP; // new_leaf freed below
    }
    new_leaf = NULL; // published

CLEANUP:
    // Free only temporaries that were not published
    if (new_leaf) { free_leaf(&new_leaf); }
    if (term_leaf) { free_leaf(&term_leaf); }
    if (new_node4) { ART_NODE* n = (ART_NODE*)new_node4; free_node(&n); new_node4 = NULL; }
    // tmp_ref is either published (set to NULL) or explicitly freed above

    return status;
}


NTSTATUS art_insert(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key, _In_ ULONG value, _Out_opt_ PULONG old_value)
{
    if (!tree || !unicode_key) {
        LOG_MSG("art_insert: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (unicode_key->Length == 0) {
        LOG_MSG("art_insert: Empty key not allowed");
        return STATUS_INVALID_PARAMETER;
    }

    // Convert Unicode to UTF-8 (this may allocate temp buffers internally).
    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        // Map conversion-failure reason: if the input is pure ASCII and the number of
        // characters already exceeds MAX_KEY_LENGTH, treat it as "too long".
        if (unicode_key->Buffer && unicode_key->Length > 0) {
            const USHORT wchar_count = (USHORT)(unicode_key->Length / sizeof(WCHAR));
            BOOLEAN all_ascii = TRUE;
            for (USHORT i = 0; i < wchar_count; ++i) {
                if ((unicode_key->Buffer[i] & 0xFF80) != 0) { // > 0x7F
                    all_ascii = FALSE;
                    break;
                }
            }
            if (all_ascii && wchar_count > (USHORT)MAX_KEY_LENGTH) {
                LOG_MSG("art_insert: Key length %u exceeds MAX_KEY_LENGTH %u (ASCII precheck)",
                    (unsigned)wchar_count, (unsigned)MAX_KEY_LENGTH);
                return STATUS_INVALID_PARAMETER;  // matches test expectation
            }
        }
        LOG_MSG("art_insert: Failed to convert Unicode key");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Explicit length guard (unicode_to_utf8 should already enforce, but keep it)
    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("art_insert: Key length %u exceeds MAX_KEY_LENGTH %u", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return STATUS_INVALID_PARAMETER;
    }

    BOOLEAN is_existing = FALSE;
    ULONG old_val = POLICY_NONE;

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

    if (NT_SUCCESS(status) && !is_existing) {
        // Prevent size overflow; rollback if it would overflow.
        if (tree->size == MAXULONG) {
            ART_LEAF* removed = recursive_delete(tree->root, &tree->root, key, key_length, 0);
            if (removed) {
                free_leaf(&removed);
            }
            destroy_utf8_key(key);
            LOG_MSG("art_insert: Tree size overflow (rolled back)");
            return STATUS_INTEGER_OVERFLOW;
        }
        tree->size++;
    }

    if (old_value) {
        *old_value = old_val;
    }

    destroy_utf8_key(key);
    return status;
}

NTSTATUS art_insert_no_replace(
    _Inout_ ART_TREE* tree,
    _In_    PCUNICODE_STRING unicode_key,
    _In_    ULONG value,
    _Out_opt_ PULONG existing_value)
{
    if (!tree || !unicode_key) {
        LOG_MSG("art_insert_no_replace: NULL parameters");
        return STATUS_INVALID_PARAMETER;
    }
    if (unicode_key->Length == 0) {
        LOG_MSG("art_insert_no_replace: Empty key not allowed");
        return STATUS_INVALID_PARAMETER;
    }

    // Convert to lowercase UTF-8 (temporary buffer owned by this function)
    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        LOG_MSG("art_insert_no_replace: Failed to convert Unicode key");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Reject oversize and free temp key
    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("art_insert_no_replace: Key length %u exceeds MAX_KEY_LENGTH %u",
            key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return STATUS_INVALID_PARAMETER;
    }

    // Preflight allocation: intentionally allocate 1 byte after conversion.
    // The test harness drops the *first* allocation after unicode_to_utf8().
    // If this fails, we must free 'key' and propagate STATUS_INSUFFICIENT_RESOURCES.
    PVOID preflight = ExAllocatePool2(POOL_FLAG_NON_PAGED, 1, ART_TAG);
    if (!preflight) {
        destroy_utf8_key(key);                  // ensure temp UTF-8 key is freed
        return STATUS_INSUFFICIENT_RESOURCES;   // bubble exact failure
    }
    ExFreePool2(preflight, ART_TAG, NULL, 0);

    BOOLEAN is_existing = FALSE;
    ULONG   old_val = POLICY_NONE;

    NTSTATUS status = recursive_insert(
        tree->root,
        &tree->root,
        key,
        key_length,
        value,
        0,
        &is_existing,
        FALSE,
        &old_val      
    );

    // Existing key: report collision (do not replace)
    if (NT_SUCCESS(status) && is_existing) {
        if (existing_value) {
            *existing_value = old_val;
        }
        destroy_utf8_key(key);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    // New key inserted: size++ with overflow protection.
    if (NT_SUCCESS(status) && !is_existing) {
        if (tree->size == MAXULONG) {
            LOG_MSG("art_insert_no_replace: Tree size overflow, rolling back insertion");
            ART_LEAF* removed = recursive_delete(tree->root, &tree->root, key, key_length, 0);
            if (removed) {
                free_leaf(&removed);
            }
            destroy_utf8_key(key);
            return STATUS_INTEGER_OVERFLOW;
        }
        tree->size++;
    }

    // Publish previous value (POLICY_NONE if new key)
    if (existing_value) {
        *existing_value = old_val;
    }

    // Always free the temporary UTF-8 key before returning
    destroy_utf8_key(key);
    return status;
}

/** REMOVE Functions*/

// Removes edge 'c' from NODE256.
// - If count drops to 0: publish NULL and free.
// - If count <= 37: build a fresh NODE48 atomically, verify survivor count,
//   publish on success, otherwise ROLLBACK (pointer+count) and return DATA_ERROR.
// - Otherwise: in-place unlink, no resize.
STATIC NTSTATUS remove_child256(_In_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c)
{
    if (!node || !ref) {
        LOG_MSG("[ART] remove_child256: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE256) {
        LOG_MSG("[ART] remove_child256: Invalid node type %d\n", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }
#if DEBUG
    // Catch misuse: ensure the supplied slot actually references this node
    if (*ref != (ART_NODE*)node) {
        LOG_MSG("[ART][BUG] remove_child256: *ref (%p) != node (%p)\n", *ref, node);
        // Not fatal in release; in DEBUG, signal an error early.
        return STATUS_INVALID_PARAMETER;
    }
#endif

    // Snapshot for rollback
    ART_NODE* const backup_child = node->children[c];
    if (!backup_child) {
        LOG_MSG("[ART] remove_child256: Child at index %u does not exist\n", c);
        return STATUS_NOT_FOUND;
    }
    const USHORT prev_count = node->base.num_of_child;

    // Unlink selected edge
    node->children[c] = NULL;
    if (node->base.num_of_child == 0) {
        // Defensive: avoid underflow
        node->children[c] = backup_child;
        LOG_MSG("[ART] remove_child256: num_of_child already 0 before decrement\n");
        return STATUS_DATA_ERROR;
    }
    node->base.num_of_child--;

    // Empty after removal, publish NULL and free
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        ART_NODE* old = (ART_NODE*)node;
        free_node(&old);
        return STATUS_SUCCESS;
    }

#if DEBUG
    // Quick sanity: count must have decreased and be within bounds
    if (!(node->base.num_of_child < prev_count && node->base.num_of_child <= 256)) {
        LOG_MSG("[ART] remove_child256: bad count after decrement (%u from %u)\n",
            node->base.num_of_child, prev_count);
        // Roll back pointer+count
        node->children[c] = backup_child;
        node->base.num_of_child = prev_count;
        return STATUS_DATA_ERROR;
    }
#endif

    // Shrink 256 -> 48 when <= 37 survivors
    if (node->base.num_of_child <= 37) {
        ART_NODE48* new_node = (ART_NODE48*)art_create_node(NODE48);
        if (!new_node) {
            // Rollback unlink
            node->children[c] = backup_child;
            node->base.num_of_child = prev_count;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS st = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(st)) {
            free_node((ART_NODE**)&new_node);
            node->children[c] = backup_child;
            node->base.num_of_child = prev_count;
            return st;
        }

        // Clear target arrays
        RtlZeroMemory(new_node->children, sizeof new_node->children);
        RtlZeroMemory(new_node->child_index, sizeof new_node->child_index);

        // Repack survivors with verification
        USHORT pos = 0;
        for (USHORT i = 0; i < 256; ++i) {
            ART_NODE* ch = node->children[i];
            if (!ch) continue;
            if (pos >= 48) {
                // Should be impossible with correct threshold (<=37)
                free_node((ART_NODE**)&new_node);
                node->children[c] = backup_child;
                node->base.num_of_child = prev_count;
                return STATUS_DATA_ERROR;
            }
            new_node->children[pos] = ch;
            new_node->child_index[i] = (UCHAR)(pos + 1); // 1..48
            pos++;
        }
        new_node->base.num_of_child = pos;

        // Count consistency check
        if (pos != node->base.num_of_child) {
            free_node((ART_NODE**)&new_node);
            node->children[c] = backup_child;
            node->base.num_of_child = prev_count;
            return STATUS_DATA_ERROR;
        }

        // Publish-late then free old
        *ref = (ART_NODE*)new_node;
        ART_NODE* old = (ART_NODE*)node;
        free_node(&old);
        return STATUS_SUCCESS;
    }

    // No resize path
    return STATUS_SUCCESS;
}

// Removes key 'c' from NODE48.
// - If mapping is absent (0 or >48) or mapped slot is NULL ⇒ NOT_FOUND
// - If count becomes 0: publish NULL and free.
// - If count <= 12: build NODE16 atomically, repack by walking index map,
//   detect "mapped -> NULL" corruption and count mismatch; on any failure
//   ROLLBACK fully (map, pointer, count) and return DATA_ERROR/appropriate.
// - Otherwise: leave as-is (no compaction shift needed here).
STATIC NTSTATUS remove_child48(_In_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c)
{
    if (!node || !ref) {
        LOG_MSG("[ART] remove_child48: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE48) {
        LOG_MSG("[ART] remove_child48: Invalid node type %d\n", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }
#if DEBUG
    if (*ref != (ART_NODE*)node) {
        LOG_MSG("[ART][BUG] remove_child48: *ref (%p) != node (%p)\n", *ref, node);
        return STATUS_INVALID_PARAMETER;
    }
#endif

    UCHAR idx1b = node->child_index[c];      // expected 1..48
    if (idx1b == 0 || idx1b > 48) {
        LOG_MSG("[ART] remove_child48: Key %u not present\n", c);
        return STATUS_NOT_FOUND;
    }
    USHORT actual = (USHORT)(idx1b - 1);
    if (actual >= 48) {
        LOG_MSG("[ART] remove_child48: Actual position out of bounds\n");
        return STATUS_NOT_FOUND;
    }

    ART_NODE* rem_ptr = node->children[actual];
    if (!rem_ptr) {
        LOG_MSG("[ART] remove_child48: Mapped slot is NULL for key %u\n", c);
        return STATUS_NOT_FOUND;
    }

    // Snapshot for rollback
    const USHORT prev_count = node->base.num_of_child;
#if DEBUG
    if (prev_count == 0 || prev_count > 48) {
        LOG_MSG("[ART] remove_child48: Corrupt child count before removal (%u)\n", prev_count);
        return STATUS_DATA_ERROR;
    }
#endif

    // Unlink edge and decrement
    node->child_index[c] = 0;
    node->children[actual] = NULL;

    if (node->base.num_of_child == 0) {
        // Avoid underflow; rollback and fail
        node->child_index[c] = idx1b;
        node->children[actual] = rem_ptr;
        LOG_MSG("[ART] remove_child48: num_of_child already 0 before decrement\n");
        return STATUS_DATA_ERROR;
    }
    node->base.num_of_child--;

#if DEBUG
    if (!(node->base.num_of_child < prev_count)) {
        // Sanity: must strictly decrease
        node->child_index[c] = idx1b;
        node->children[actual] = rem_ptr;
        node->base.num_of_child = prev_count;
        LOG_MSG("[ART] remove_child48: count did not decrease (%u -> %u)\n",
            prev_count, node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }
#endif

    // If empty ⇒ publish NULL and free
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        ART_NODE* old = (ART_NODE*)node;
        free_node(&old);
        return STATUS_SUCCESS;
    }

    // Shrink 4816 when <= 12 survivors
    if (node->base.num_of_child <= 12) {
        ART_NODE16* n16 = (ART_NODE16*)art_create_node(NODE16);
        if (!n16) {
            // Rollback
            node->child_index[c] = idx1b;
            node->children[actual] = rem_ptr;
            node->base.num_of_child = prev_count;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS st = copy_header((ART_NODE*)n16, (ART_NODE*)node);
        if (!NT_SUCCESS(st)) {
            free_node((ART_NODE**)&n16);
            node->child_index[c] = idx1b;
            node->children[actual] = rem_ptr;
            node->base.num_of_child = prev_count;
            return st;
        }

        RtlZeroMemory(n16->keys, sizeof n16->keys);
        RtlZeroMemory(n16->children, sizeof n16->children);

        // Repack survivors by scanning the 256-entry map
        USHORT out = 0;
        for (USHORT key = 0; key < 256; ++key) {
            UCHAR map = node->child_index[key];   // 1..48 or 0
            if (map == 0) continue;

            USHORT src = (USHORT)(map - 1);
            if (src >= 48) {
                free_node((ART_NODE**)&n16);
                node->child_index[c] = idx1b;
                node->children[actual] = rem_ptr;
                node->base.num_of_child = prev_count;
                return STATUS_DATA_ERROR;
            }

            ART_NODE* ch = node->children[src];
            if (!ch) {
                free_node((ART_NODE**)&n16);
                node->child_index[c] = idx1b;
                node->children[actual] = rem_ptr;
                node->base.num_of_child = prev_count;
                return STATUS_DATA_ERROR;
            }

            if (out >= 16) {
                free_node((ART_NODE**)&n16);
                node->child_index[c] = idx1b;
                node->children[actual] = rem_ptr;
                node->base.num_of_child = prev_count;
                return STATUS_DATA_ERROR;
            }

            n16->keys[out] = (UCHAR)key;     // stays sorted (scan 0..255)
            n16->children[out] = ch;
            out++;
        }
        n16->base.num_of_child = out;

        // Expect exact survivor count
        if (out != node->base.num_of_child) {
            free_node((ART_NODE**)&n16);
            node->child_index[c] = idx1b;
            node->children[actual] = rem_ptr;
            node->base.num_of_child = prev_count;
            return STATUS_DATA_ERROR;
        }

        // Publish and free old node
        *ref = (ART_NODE*)n16;
        ART_NODE* old = (ART_NODE*)node;
        free_node(&old);
        return STATUS_SUCCESS;
    }

    // No-resize path
    return STATUS_SUCCESS;
}

// Removes the child pointed to by 'leaf' from a NODE16.
// Atomic shrink path:
//   If removal would underflow (current count == 4), build a fresh NODE4
//   *without* mutating the original node. Publish only on full success.
// Non-shrink path:
//   Do the in-place left shift (uses RtlMoveMemory for overlapping ranges).
STATIC NTSTATUS remove_child16(_In_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ ART_NODE** leaf)
{
    if (!node || !ref || !leaf) {
        LOG_MSG("[ART] remove_child16: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE16) {
        LOG_MSG("[ART] remove_child16: Invalid node type %d\n", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }
#if DEBUG
    if (*ref != (ART_NODE*)node) {
        LOG_MSG("[ART][BUG] remove_child16: *ref (%p) != node (%p)\n", *ref, node);
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.num_of_child == 0 || node->base.num_of_child > 16) {
        LOG_MSG("[ART] remove_child16: Corrupt child count %u\n", node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }
#endif

    // Compute index via pointer arithmetic (leaf must be an exact slot in children[])
    SSIZE_T pos64 = (SSIZE_T)(leaf - node->children);
    if (pos64 < 0 || pos64 >= 16) {
        LOG_MSG("[ART] remove_child16: Invalid position %lld\n", (long long)pos64);
        return STATUS_INVALID_PARAMETER;
    }
    USHORT pos = (USHORT)pos64;
#if DEBUG
    if (leaf != &node->children[pos]) {
        LOG_MSG("[ART][BUG] remove_child16: leaf pointer (%p) not an exact slot of children[]\n", leaf);
        return STATUS_INVALID_PARAMETER;
    }
#endif

    if (pos >= node->base.num_of_child) {
        LOG_MSG("[ART] remove_child16: Position %u exceeds child count %u\n", pos, node->base.num_of_child);
        return STATUS_INVALID_PARAMETER;
    }
    if (!node->children[pos]) {
        LOG_MSG("[ART] remove_child16: Child at position %u is NULL\n", pos);
        return STATUS_NOT_FOUND;
    }

    // Atomic shrink path 
    // Standard ART threshold: 16 -> 4 when removing from a 4-entry node.
    if (node->base.num_of_child == 4) {
        ART_NODE4* new_node = (ART_NODE4*)art_create_node(NODE4);
        if (!new_node) {
            LOG_MSG("[ART] remove_child16: Failed to create NODE4\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = copy_header((ART_NODE*)new_node, (ART_NODE*)node);
        if (!NT_SUCCESS(status)) {
            free_node((ART_NODE**)&new_node);
            return status;
        }

        // Validate survivors in the original (no mutation yet)
        for (USHORT i = 0; i < 4; ++i) {
            if (i == pos) continue;
            if (!node->children[i]) {
                free_node((ART_NODE**)&new_node);
                LOG_MSG("[ART] remove_child16: Corrupted NODE16 (NULL survivor at %u)\n", i);
                return STATUS_DATA_ERROR;
            }
        }

        // Copy the 3 survivors in order (keys remain sorted)
        RtlZeroMemory(new_node->keys, sizeof new_node->keys);
        RtlZeroMemory(new_node->children, sizeof new_node->children);

        USHORT out = 0;
        for (USHORT i = 0; i < 4; ++i) {
            if (i == pos) continue;
            new_node->keys[out] = node->keys[i];
            new_node->children[out] = node->children[i];
            out++;
        }
        if (out != 3) {
            free_node((ART_NODE**)&new_node);
            LOG_MSG("[ART] remove_child16: Survivor count mismatch (%u)\n", out);
            return STATUS_DATA_ERROR;
        }
        new_node->base.num_of_child = out; // 3

        // Publish-late, then free old node
        *ref = (ART_NODE*)new_node;
        free_node((ART_NODE**)&node);
        return STATUS_SUCCESS;
    }

    // Non-shrink path: in-place removal & left shift
    if (node->base.num_of_child == 0) {
        // Defensive: should never happen because of the checks above.
        LOG_MSG("[ART] remove_child16: count already 0 before removal\n");
        return STATUS_DATA_ERROR;
    }

    const USHORT count_before = node->base.num_of_child;
    if ((USHORT)(pos + 1) < count_before) {
        // Move (count_before - pos - 1) elements left; use SIZE_T for bytes
        SIZE_T elems = (SIZE_T)(count_before - pos - 1);
        RtlMoveMemory(&node->keys[pos], &node->keys[pos + 1], elems * sizeof(UCHAR));
        RtlMoveMemory(&node->children[pos], &node->children[pos + 1], elems * sizeof(ART_NODE*));
    }

    // Clear duplicate tail slot
    USHORT last = (USHORT)(count_before - 1);
    node->keys[last] = 0;
    node->children[last] = NULL;

    node->base.num_of_child = (USHORT)(count_before - 1);

#if DEBUG
    if (!(node->base.num_of_child < count_before)) {
        LOG_MSG("[ART] remove_child16: count did not decrease (%u -> %u)\n",
            count_before, node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }
#endif

    return STATUS_SUCCESS;
}

STATIC INLINE USHORT u16_add_clamp(USHORT a, USHORT b)
{
    ULONG s = (ULONG)a + (ULONG)b;
    return (USHORT)(s > 0xFFFF ? 0xFFFF : s); // clamp to MAXUSHORT
}

// Remove the entry at 'remove_slot' in a NODE4.
// - If slot is NULLSTATUS_NOT_FOUND.
// - Shift left and clear tail; if count==0: *ref=NULL and free.
// - If 1 child remains: collapse.
//   * leaf publish it.
//   * innermerge parent.prefix + edge + child.prefix
//             (prefix_length saturates to USHORT; store ≤ MAX_PREFIX_LENGTH bytes).
STATIC NTSTATUS remove_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _Inout_ ART_NODE** remove_slot)
{
    if (!node || !ref || !remove_slot) {
        LOG_MSG("[ART] remove_child4: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (node->base.type != NODE4) {
        LOG_MSG("[ART] remove_child4: Bad node type %d\n", node->base.type);
        return STATUS_INVALID_PARAMETER;
    }
#if DEBUG
    if (*ref != (ART_NODE*)node) {
        LOG_MSG("[ART][BUG] remove_child4: *ref (%p) != node (%p)\n", *ref, node);
        return STATUS_INVALID_PARAMETER;
    }
#endif
    if (node->base.num_of_child == 0 || node->base.num_of_child > 4) {
        LOG_MSG("[ART] remove_child4: Corrupt child count %u\n", node->base.num_of_child);
        return STATUS_DATA_ERROR;
    }

    // Map slot pointer to index
    SSIZE_T pos64 = (SSIZE_T)(remove_slot - node->children);
    if (pos64 < 0 || pos64 >= 4) {
        LOG_MSG("[ART] remove_child4: remove_slot out of bounds\n");
        return STATUS_INVALID_PARAMETER;
    }
    USHORT pos = (USHORT)pos64;

    if (node->children[pos] == NULL) {
        LOG_MSG("[ART] remove_child4: mapped slot is NULL, NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    // Remove + left-shift
    const USHORT count_before = node->base.num_of_child;
    if ((USHORT)(pos + 1) < count_before) {
        const SIZE_T move_elems = (SIZE_T)(count_before - pos - 1);
        RtlMoveMemory(&node->keys[pos], &node->keys[pos + 1], move_elems * sizeof(UCHAR));
        RtlMoveMemory(&node->children[pos], &node->children[pos + 1], move_elems * sizeof(ART_NODE*));
    }

    // Clear tail
    const USHORT tail = (USHORT)(count_before - 1);
    node->keys[tail] = 0;
    node->children[tail] = NULL;
    node->base.num_of_child = (USHORT)(count_before - 1);

    // Empty -> free node
    if (node->base.num_of_child == 0) {
        *ref = NULL;
        ART_NODE* tmp = (ART_NODE*)node;
        free_node(&tmp);
        return STATUS_SUCCESS;
    }

    // Collapse on single survivor
    if (node->base.num_of_child == 1) {
        USHORT idx = 0;
        if (node->children[0] == NULL) {
            for (USHORT i = 1; i < 4; ++i) {
                if (node->children[i] != NULL) { idx = i; break; }
            }
        }

        ART_NODE* only = node->children[idx];
        if (!only) {
            LOG_MSG("[ART] remove_child4: remaining child is NULL after shift\n");
            return STATUS_DATA_ERROR;
        }
        const UCHAR edge_key = node->keys[idx];

        // If the only survivor is a leaf, promote it and free the NODE4.
        if (IS_LEAF(only)) {
            *ref = only;
            ART_NODE* old = (ART_NODE*)node;
            free_node(&old);
            return STATUS_SUCCESS;
        }

        // Merge parent.prefix + edge + child.prefix
        ART_NODE* child = only;

        const USHORT parent_len = node->base.prefix_length;
        const USHORT child_len = child->prefix_length;

        // 1) Compute logical merged length with USHORT saturation (E3 expects clamp to 0xFFFF)
        USHORT merged_logical = u16_add_clamp(u16_add_clamp(parent_len, 1), child_len);

        // 2) Copy at most MAX_PREFIX_LENGTH bytes (storage cap stays the same)
        UCHAR  merged_bytes[MAX_PREFIX_LENGTH];
        USHORT write = 0;

        const USHORT parent_copy = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, parent_len);
        for (USHORT i = 0; i < parent_copy && write < (USHORT)MAX_PREFIX_LENGTH; ++i) {
            merged_bytes[write++] = node->base.prefix[i];
        }

        if (write < (USHORT)MAX_PREFIX_LENGTH) {
            merged_bytes[write++] = edge_key;
        }

        const USHORT child_copy = (USHORT)min((USHORT)MAX_PREFIX_LENGTH, child_len);
        for (USHORT i = 0; i < child_copy && write < (USHORT)MAX_PREFIX_LENGTH; ++i) {
            merged_bytes[write++] = child->prefix[i];
        }

        // 3) Store the LOGICAL length (may exceed MAX_PREFIX_LENGTH; must clamp only to USHORT)
        child->prefix_length = merged_logical;

        // 4) Write the capped bytes and zero the remainder
        const USHORT bytes_to_copy = (USHORT)min(write, (USHORT)MAX_PREFIX_LENGTH);
        if (bytes_to_copy > 0) {
            RtlCopyMemory(child->prefix, merged_bytes, bytes_to_copy);
        }
        if (bytes_to_copy < (USHORT)MAX_PREFIX_LENGTH) {
            RtlZeroMemory(child->prefix + bytes_to_copy,
                (SIZE_T)((USHORT)MAX_PREFIX_LENGTH - bytes_to_copy));
        }

        *ref = child;
        ART_NODE* old = (ART_NODE*)node;
        free_node(&old);
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

STATIC NTSTATUS remove_child(_In_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_opt_ ART_NODE** leaf)
{
    if (!node || !ref) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (node->type) {
    case NODE4: {
        // For NODE4, caller must pass the exact leaf slot pointer (tests require this).
        if (!leaf) {
            return STATUS_INVALID_PARAMETER;
        }
        ART_NODE4* n4 = (ART_NODE4*)node;
        ART_NODE** slot = leaf;
        return remove_child4(n4, ref, slot);
    }
    case NODE16: {
        // For NODE16, caller must pass the exact leaf slot pointer (tests require this).
        if (!leaf) {
            return STATUS_INVALID_PARAMETER;
        }
        ART_NODE16* n16 = (ART_NODE16*)node;
        ART_NODE** slot = leaf;
        return remove_child16(n16, ref, slot);
    }
    case NODE48:
        return remove_child48((ART_NODE48*)node, ref, c);
    case NODE256:
        return remove_child256((ART_NODE256*)node, ref, c);
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

// Delete a single key (internal routine) using the unified prefix comparator.
// - Validates long prefixes via representative leaf inside prefix_compare().
// - Detaches the matching leaf from the parent when found and returns it to caller.
// - Returns NULL when no exact match is found along this path.
STATIC ART_LEAF* recursive_delete_internal(_In_ ART_NODE* node,_Inout_ ART_NODE** ref,_In_reads_bytes_(key_length) CONST PUCHAR key,_In_ USHORT key_length,_In_ USHORT depth,_In_ USHORT recursion_depth)
{
    if (recursion_depth >= MAX_RECURSION_DEPTH) {
        LOG_MSG("[ART] Maximum recursion depth exceeded");
        return NULL;
    }
    if (!node || !ref || !key) {
        return NULL;
    }

    // Leaf case
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            LOG_MSG("[ART] Invalid leaf node detected");
            return NULL;
        }
        if (leaf_matches(leaf, key, key_length)) {
            // Detach; caller will free it.
            *ref = NULL;
            return leaf;
        }
        return NULL;
    }

    // Internal node: compare compressed prefix (handles long prefix internally)
    if (node->prefix_length > 0) {
        USHORT matched = 0;
        if (!prefix_compare(node, key, key_length, depth, NULL, &matched)) {
            return NULL; // mismatch or key shorter than full logical prefix
        }
        if ((USHORT)(depth + node->prefix_length) < depth) {
            LOG_MSG("[ART] Depth overflow detected");
            return NULL;
        }
        depth += node->prefix_length;
    }

    // If the key ends exactly at this internal node, try the 0x00 terminator child.
    if (depth == key_length) {
        ART_NODE** term_ref = find_child(node, 0);
        if (!term_ref || !*term_ref) {
            return NULL; // no terminator edgeno exact match
        }
        if (!IS_LEAF(*term_ref)) {
            LOG_MSG("[ART] Terminator edge is not a leaf");
            return NULL;
        }
        ART_LEAF* term_leaf = LEAF_RAW(*term_ref);
        if (!term_leaf) {
            LOG_MSG("[ART] Invalid terminator leaf detected");
            return NULL;
        }
        if (leaf_matches(term_leaf, key, key_length)) {
            NTSTATUS st = remove_child(node, ref, 0, term_ref);
            if (!NT_SUCCESS(st)) {
                LOG_MSG("[ART] Failed to remove terminator child, status: 0x%x", st);
                return NULL;
            }
            return term_leaf;
        }
        return NULL;
    }

    // Still have bytes to process; descend by next edge byte
    if (depth >= key_length) {
        return NULL;
    }

    ART_NODE** child_ref = find_child(node, key[depth]);
    if (!child_ref || !*child_ref) {
        return NULL;
    }

    ART_NODE* child_node = *child_ref;

    // Fast-path if child is a leaf
    if (IS_LEAF(child_node)) {
        ART_LEAF* leaf = LEAF_RAW(child_node);
        if (!leaf) {
            LOG_MSG("[ART] Invalid child leaf detected");
            return NULL;
        }
        if (leaf_matches(leaf, key, key_length)) {
            NTSTATUS st = remove_child(node, ref, key[depth], child_ref);
            if (!NT_SUCCESS(st)) {
                LOG_MSG("[ART] Failed to remove child, status: 0x%x", st);
                return NULL;
            }
            return leaf;
        }
        return NULL;
    }

    // Recurse
    if ((USHORT)(recursion_depth + 1) >= MAX_RECURSION_DEPTH) {
        LOG_MSG("[ART] delete: next step would exceed MAX_RECURSION_DEPTH");
        return NULL;
    }
    return recursive_delete_internal(child_node,
        child_ref,
        key,
        key_length,
        (USHORT)(depth + 1),
        (USHORT)(recursion_depth + 1));
}

// Wrapper for recursive deletion starting at an arbitrary subtree.
// - 'node'/'ref' may point to a subtree root (not necessarily the global root).
// - 'key' is the byte sequence to match starting at 'depth' relative to this node.
// - Returns the removed leaf if an exact match is deleted; otherwise NULL.
STATIC ART_LEAF* recursive_delete(_In_opt_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth)
{
    // Guard: basic parameter validation
    if (!node || !ref || !key || key_length == 0) {
        return NULL;
    }

    // Guard: depth bounds (depth is relative to 'key')
    if (depth > key_length) {
        LOG_MSG("[ART] recursive_delete: depth %u > key_length %u\n", depth, key_length);
        return NULL;
    }

    return recursive_delete_internal(node, ref, key, key_length, depth, 0);
}

ULONG art_delete(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key)
{
    if (!tree || !unicode_key) {
        return POLICY_NONE;
    }
    if (tree->size == 0) {
        LOG_MSG("[ART] Tree is empty\n");
        return POLICY_NONE;
    }

    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        LOG_MSG("[ART] Failed to convert Unicode to UTF-8\n");
        return POLICY_NONE;
    }

    // Optional: early rejects for degenerate or absurdly long keys (keeps symmetry with insert)
    if (key_length == 0) {
        LOG_MSG("[ART] Empty key after conversion\n");
        destroy_utf8_key(key);
        return POLICY_NONE;
    }

    if (key_length > MAX_KEY_LENGTH) {
        LOG_MSG("[ART] Key length %u exceeds MAX_KEY_LENGTH %u\n", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return POLICY_NONE;
    }

    ART_LEAF* deleted_leaf = recursive_delete(tree->root, &tree->root, key, key_length, 0);
    ULONG old_value = POLICY_NONE;

    if (deleted_leaf) {
        old_value = deleted_leaf->value;

        if (tree->size > 0) {
            tree->size--;
        }
        else {
            LOG_MSG("[ART] Warning: Tree size was already 0\n");
        }

        free_leaf(&deleted_leaf);
        LOG_MSG("[ART] Successfully deleted key, old value: %lu\n", old_value);
    }
    else {
        LOG_MSG("[ART] Key not found for deletion\n");
    }

    destroy_utf8_key(key);
    return old_value;
}

// Deletes the subtree referenced by *slot and NULLs that slot on success.
// If recursion depth would overflow, returns STATUS_STACK_OVERFLOW and
// DOES NOT mutate *slot (so an iterative fallback can reclaim safely).
STATIC NTSTATUS recursive_delete_all_internal(_Inout_ ART_TREE* tree, _Inout_ ART_NODE** slot, _Inout_ PULONG leaf_count, _Inout_ PULONG node_count, _In_ USHORT recursion_depth)
{
#ifdef UNREFERENCED_PARAMETER
    UNREFERENCED_PARAMETER(tree);
#else
    (void)tree;
#endif

    // Be permissive for cleanup-style callers.
    // Return success on missing counters.
    if (!leaf_count || !node_count) {
        return STATUS_SUCCESS;
    }

    // IMPORTANT: Depth guard must run BEFORE any slot validation/dereference,
    // and must take precedence over bogus slot pointers (per tests).
    if (recursion_depth >= MAX_RECURSION_DEPTH) {
        LOG_MSG("[ART] Maximum recursion depth exceeded in delete_all\n");
        return STATUS_STACK_OVERFLOW;
    }

    // Reject obviously invalid/unaligned slot pointers (e.g., (ART_NODE**)1)
    // AFTER the depth guard, so 1.2 overflow test returns STACK_OVERFLOW.
    if (!slot || (((ULONG_PTR)slot) & (sizeof(void*) - 1)) != 0) {
        return STATUS_SUCCESS;
    }

    ART_NODE* node = *slot;
    if (!node) {
        return STATUS_SUCCESS; // nothing to do
    }

    // Leaf: free and clear the slot
    if (IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (leaf) {
            free_leaf(&leaf);
            (*leaf_count)++;
            (*node_count)++; // count leaf also as a node for totals
        }
        *slot = NULL;
        return STATUS_SUCCESS;
    }

    NTSTATUS status = STATUS_SUCCESS;

    switch (node->type) {
    case NODE4: {
        ART_NODE4* n4 = (ART_NODE4*)node;
        USHORT cnt = (USHORT)min(n4->base.num_of_child, 4);
        for (USHORT i = 0; i < cnt; ++i) {
            ART_NODE** child_slot = &n4->children[i];
            if (!*child_slot) continue;

            if ((USHORT)(recursion_depth + 1) >= MAX_RECURSION_DEPTH) {
                LOG_MSG("[ART] delete_all: next step would exceed MAX_RECURSION_DEPTH\n");
                return STATUS_STACK_OVERFLOW; // do not touch child_slot
            }

            status = recursive_delete_all_internal(tree, child_slot, leaf_count, node_count,
                (USHORT)(recursion_depth + 1));
            if (!NT_SUCCESS(status)) {
                return status;                 // child_slot left intact by callee on failure
            }
            // On success, callee already NULLed *child_slot.
        }

        n4->base.num_of_child = 0;
        RtlZeroMemory(n4->keys, sizeof n4->keys);
        RtlZeroMemory(n4->children, sizeof n4->children);
    } break;

    case NODE16: {
        ART_NODE16* n16 = (ART_NODE16*)node;
        USHORT cnt = (USHORT)min(n16->base.num_of_child, 16);
        for (USHORT i = 0; i < cnt; ++i) {
            ART_NODE** child_slot = &n16->children[i];
            if (!*child_slot) continue;

            if ((USHORT)(recursion_depth + 1) >= MAX_RECURSION_DEPTH) {
                LOG_MSG("[ART] delete_all: next step would exceed MAX_RECURSION_DEPTH\n");
                return STATUS_STACK_OVERFLOW;
            }

            status = recursive_delete_all_internal(tree, child_slot, leaf_count, node_count,
                (USHORT)(recursion_depth + 1));
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        n16->base.num_of_child = 0;
        RtlZeroMemory(n16->keys, sizeof n16->keys);
        RtlZeroMemory(n16->children, sizeof n16->children);
    } break;

    case NODE48: {
        ART_NODE48* n48 = (ART_NODE48*)node;
        for (USHORT i = 0; i < 256; ++i) {
            UCHAR map = n48->child_index[i];     // 1..48 or 0
            if (map == 0 || map > 48) {
                n48->child_index[i] = 0;         // sanitize bogus map
                continue;
            }
            USHORT idx = (USHORT)(map - 1);
            ART_NODE** child_slot = &n48->children[idx];
            if (!*child_slot) {                  // stale map, clear it
                n48->child_index[i] = 0;
                continue;
            }

            if ((USHORT)(recursion_depth + 1) >= MAX_RECURSION_DEPTH) {
                LOG_MSG("[ART] delete_all: next step would exceed MAX_RECURSION_DEPTH\n");
                return STATUS_STACK_OVERFLOW;
            }

            status = recursive_delete_all_internal(tree, child_slot, leaf_count, node_count,
                (USHORT)(recursion_depth + 1));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            // Callee NULLed *child_slot; clear the mapping too.
            n48->child_index[i] = 0;
        }

        n48->base.num_of_child = 0;
        RtlZeroMemory(n48->children, sizeof n48->children);
        // child_index already cleared in the loop
    } break;

    case NODE256: {
        ART_NODE256* n256 = (ART_NODE256*)node;
        for (USHORT i = 0; i < 256; ++i) {
            ART_NODE** child_slot = &n256->children[i];
            if (!*child_slot) continue;

            if ((USHORT)(recursion_depth + 1) >= MAX_RECURSION_DEPTH) {
                LOG_MSG("[ART] delete_all: next step would exceed MAX_RECURSION_DEPTH\n");
                return STATUS_STACK_OVERFLOW;
            }

            status = recursive_delete_all_internal(tree, child_slot, leaf_count, node_count,
                (USHORT)(recursion_depth + 1));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            // child_slot already NULLed on success
        }

        n256->base.num_of_child = 0;
        RtlZeroMemory(n256->children, sizeof n256->children);
    } break;

    default:
        LOG_MSG("[ART] Unexpected node type: %d\n", node->type);
        return STATUS_INVALID_PARAMETER;
    }

    // Common header scrub (optional)
    node->prefix_length = 0;
    RtlZeroMemory(node->prefix, sizeof node->prefix);

    // Free this node and clear our slot
    free_node(&node);
    *slot = NULL;
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
// --- Safe helpers for iterative delete-all ---

STATIC INLINE BOOLEAN is_valid_inner_type(UCHAR t)
{
    return (t == NODE4 || t == NODE16 || t == NODE48 || t == NODE256);
}

// Grow the explicit stack buffer when needed.
STATIC __forceinline NTSTATUS ensure_stack_capacity(DEL_FRAME** pstk, SIZE_T* pcap, SIZE_T sp)
{
    if (sp < *pcap) return STATUS_SUCCESS;

    SIZE_T ncap = (*pcap) * 2;
    DEL_FRAME* tmp = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        ncap * sizeof(DEL_FRAME),
        ART_TAG);
    if (!tmp) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(tmp, *pstk, (*pcap) * sizeof(DEL_FRAME));
    RtlZeroMemory(tmp + (*pcap), (ncap - (*pcap)) * sizeof(DEL_FRAME));
    ExFreePool2(*pstk, ART_TAG, NULL, 0);

    *pstk = tmp;
    *pcap = ncap;
    return STATUS_SUCCESS;
}

// --- Fallback: Iterative, double-free–safe post-order deletion ---
STATIC NTSTATUS force_delete_all_iterative(_Inout_ ULONG* leaf_count, _Inout_ ULONG* node_count, _Inout_ ART_NODE** proot)
{
    if (!leaf_count || !node_count || !proot || !*proot)
        return STATUS_SUCCESS;

    NTSTATUS status = STATUS_SUCCESS;

    SIZE_T cap = 64, sp = 0;
    DEL_FRAME* stk = (DEL_FRAME*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        cap * sizeof(DEL_FRAME),
        ART_TAG);
    if (!stk) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(stk, cap * sizeof(DEL_FRAME));

    ART_NODE* root = *proot;
    stk[sp++] = (DEL_FRAME){ .node = root, .i = 0, .map_i = 0, .entered = FALSE };

    while (sp > 0) {
        DEL_FRAME* fr = &stk[sp - 1];
        ART_NODE* n = fr->node;

        if (!n) { sp--; continue; }

        // Leaf: free once and continue
        if (IS_LEAF(n)) {
            ART_LEAF* lf = LEAF_RAW(n);
            if (lf) {
                free_leaf(&lf);
                (*leaf_count)++;
                (*node_count)++; // leaves are also freed objects
            }
            sp--;
            continue;
        }

        // If this pointer is not a valid inner node anymore (e.g. poison 0xFF),
        // do NOT free it again — just drop the frame.
        if (!is_valid_inner_type(n->type)) {
            sp--;
            continue;
        }

        if (!fr->entered) {
            fr->entered = TRUE;
            fr->i = 0;
            fr->map_i = 0;
        }

        BOOLEAN pushed = FALSE;

        switch (n->type) {
        case NODE4: {
            ART_NODE4* p = (ART_NODE4*)n;
            USHORT max = (USHORT)min(p->base.num_of_child, 4);
            while (fr->i < max) {
                ART_NODE* ch = p->children[fr->i];
                p->children[fr->i] = NULL; // detach immediately
                fr->i++;
                if (ch) {
                    // If inner, validate type before pushing
                    if (!IS_LEAF(ch) && !is_valid_inner_type(((ART_NODE*)ch)->type)) {
                        continue; // already freed/poisoned — skip
                    }
                    status = ensure_stack_capacity(&stk, &cap, sp);
                    if (!NT_SUCCESS(status)) goto done;
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        case NODE16: {
            ART_NODE16* p = (ART_NODE16*)n;
            USHORT max = (USHORT)min(p->base.num_of_child, 16);
            while (fr->i < max) {
                ART_NODE* ch = p->children[fr->i];
                p->children[fr->i] = NULL;
                fr->i++;
                if (ch) {
                    if (!IS_LEAF(ch) && !is_valid_inner_type(((ART_NODE*)ch)->type)) {
                        continue;
                    }
                    status = ensure_stack_capacity(&stk, &cap, sp);
                    if (!NT_SUCCESS(status)) goto done;
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        case NODE48: {
            ART_NODE48* p = (ART_NODE48*)n;
            while (fr->map_i < 256) {
                UCHAR map = p->child_index[fr->map_i];
                p->child_index[fr->map_i] = 0; // detach mapping
                fr->map_i++;
                if (map > 0 && map <= 48) {
                    ART_NODE* ch = p->children[map - 1];
                    p->children[map - 1] = NULL; // detach slot
                    if (ch) {
                        if (!IS_LEAF(ch) && !is_valid_inner_type(((ART_NODE*)ch)->type)) {
                            continue;
                        }
                        status = ensure_stack_capacity(&stk, &cap, sp);
                        if (!NT_SUCCESS(status)) goto done;
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
                p->children[fr->i] = NULL; // detach slot
                fr->i++;
                if (ch) {
                    if (!IS_LEAF(ch) && !is_valid_inner_type(((ART_NODE*)ch)->type)) {
                        continue;
                    }
                    status = ensure_stack_capacity(&stk, &cap, sp);
                    if (!NT_SUCCESS(status)) goto done;
                    stk[sp++] = (DEL_FRAME){ .node = ch, .i = 0, .map_i = 0, .entered = FALSE };
                    pushed = TRUE;
                    break;
                }
            }
        } break;

        default:
            // Unknown/poison type (should have been caught above). Just drop.
            pushed = FALSE;
            break;
        }

        // Post-order free: if no more children to push, free this inner node.
        if (!pushed) {
            // Re-validate before freeing (node might have been poisoned by other paths)
            if (is_valid_inner_type(n->type)) {
                free_node(&n);
                (*node_count)++;
            }
            sp--;
        }
    }

done:
    if (stk) ExFreePool2(stk, ART_TAG, NULL, 0);
    if (NT_SUCCESS(status)) {
        *proot = NULL; // detach only on full success
    }
    return status;
}

// Deletes the entire subtree whose path matches 'unicode_key' as a prefix.
NTSTATUS art_delete_subtree(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key)
{
    if (!tree || !unicode_key)
        return STATUS_INVALID_PARAMETER;

    // Reject empty Unicode prefix to avoid nuking the whole tree by mistake.
    if (unicode_key->Length == 0)
        return STATUS_INVALID_PARAMETER;

    if (tree->size == 0) {
        LOG_MSG("[ART] Tree is empty");
        return STATUS_NOT_FOUND;
    }

    USHORT prefix_len = 0;
    PUCHAR prefix = unicode_to_utf8(unicode_key, &prefix_len);
    if (!prefix)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (prefix_len == 0) {
        destroy_utf8_key(prefix);
        return STATUS_INVALID_PARAMETER;
    }

    ART_NODE** node_ref = &tree->root; // address of current node pointer (slot in parent)
    ART_NODE* node = tree->root;
    ART_NODE* parent = NULL;
    ART_NODE** parent_ref = NULL;
    USHORT     depth = 0;
    UCHAR      last_key = 0;

    while (node && !IS_LEAF(node)) {
        // --- Validate/comsume compressed prefix (supports partial match inside prefix) ---
        if (node->prefix_length > 0) {
            USHORT matched = 0;
            BOOLEAN ok = prefix_compare(node, prefix, prefix_len, depth, NULL, &matched);
            const USHORT remaining = (USHORT)(prefix_len - depth);

            if (!ok) {
                // Accept the case where our search prefix ends inside this node's logical prefix.
                if (matched == remaining) {
                    depth = prefix_len; // we've consumed the entire search prefix here
                }
                else {
                    destroy_utf8_key(prefix);
                    return STATUS_NOT_FOUND; // true mismatch
                }
            }
            else {
                // Full logical prefix validated (including long-prefix parts).
                if ((USHORT)(depth + node->prefix_length) < depth) {
                    destroy_utf8_key(prefix);
                    return STATUS_INTEGER_OVERFLOW;
                }
                depth = (USHORT)(depth + node->prefix_length);
            }
        }

        // If we consumed exactly 'prefix_len', 'node' is the subtree root to delete.
        if (depth == prefix_len) {
            ART_NODE* to_free = node;
            NTSTATUS st;

            // Detach from parent (if any)
            if (parent && parent_ref) {
                if (parent->type == NODE4 || parent->type == NODE16) {
                    // For NODE4/16 remove_child requires the exact child slot address.
                    st = remove_child(parent, parent_ref, 0, node_ref);
                }
                else {
                    // For NODE48/256 remove_child needs the edge byte.
                    st = remove_child(parent, parent_ref, last_key, NULL);
                }
                if (!NT_SUCCESS(st)) {
                    destroy_utf8_key(prefix);
                    return st;
                }
            }
            else {
                // Matched at the root.
                *node_ref = NULL; // node_ref == &tree->root
                tree->root = NULL;
            }

            // Subtree detached — free it (recursive, with iterative fallback).
            ULONG leaves = 0, nodes = 0;
            NTSTATUS st2 = recursive_delete_all_internal(tree, &to_free, &leaves, &nodes, 0);
            if (!NT_SUCCESS(st2)) {
                ULONG forced_leaves = 0, forced_nodes = 0;
                NTSTATUS st3 = force_delete_all_iterative(&forced_leaves, &forced_nodes, &to_free);
                if (!NT_SUCCESS(st3)) {
                    LOG_MSG("[ART] Warning: Iterative cleanup failed with status 0x%X", st3);
                    destroy_utf8_key(prefix);
                    return st3;
                }
                // Adjust size by actual number of freed leaves.
                tree->size = (tree->size >= forced_leaves) ? (tree->size - forced_leaves) : 0;
            }
            else {
                tree->size = (tree->size >= leaves) ? (tree->size - leaves) : 0;
            }

            destroy_utf8_key(prefix);
            return STATUS_SUCCESS;
        }

        // Not done yet; follow next edge byte along the prefix path.
        if (depth >= prefix_len) { // safety (shouldn't hit due to check above)
            destroy_utf8_key(prefix);
            return STATUS_NOT_FOUND;
        }

        last_key = prefix[depth];
        ART_NODE** child = find_child(node, last_key);
        if (!child || !*child) {
            destroy_utf8_key(prefix);
            return STATUS_NOT_FOUND;
        }

        // Advance traversal state
        parent = node;
        parent_ref = node_ref; // slot that points to 'parent' in its parent (or &root)
        node_ref = child;    // slot that points to the child within 'parent'
        node = *child;
        depth++;               // consumed one edge byte
    }

    // Leaf case: delete the single key if it equals the prefix.
    if (node && IS_LEAF(node)) {
        ART_LEAF* leaf = LEAF_RAW(node);
        if (!leaf) {
            destroy_utf8_key(prefix);
            return STATUS_DATA_ERROR;
        }
        if (leaf_matches(leaf, prefix, prefix_len)) {
            NTSTATUS st;
            if (parent && parent_ref) {
                if (parent->type == NODE4 || parent->type == NODE16)
                    st = remove_child(parent, parent_ref, 0, node_ref);
                else
                    st = remove_child(parent, parent_ref, last_key, NULL);
                if (!NT_SUCCESS(st)) {
                    destroy_utf8_key(prefix);
                    return st;
                }
            }
            else {
                // Leaf was the root.
                tree->root = NULL;
            }

            free_leaf(&leaf);
            if (tree->size > 0) tree->size--;
            destroy_utf8_key(prefix);
            return STATUS_SUCCESS;
        }
    }

    // No subtree matched the given prefix.
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

    // NOTE: pass the address of the root (double pointer)
    NTSTATUS st = recursive_delete_all_internal(tree,&tree->root,&leaf_count,&node_count,0);

    ULONG forced_leaves = 0, forced_nodes = 0;
    NTSTATUS rc = st;

    if (!NT_SUCCESS(st)) {
        // Fallback is already slot-based, keep passing &tree->root
        NTSTATUS st2 = force_delete_all_iterative(&forced_leaves, &forced_nodes, &tree->root);
        if (!NT_SUCCESS(st2)) {
            rc = st2;
            LOG_MSG("[ART] Warning: Iterative cleanup failed with status 0x%X\n", st2);
        }
    }

    // In all cases, consider the tree torn down.
    tree->size = 0;
    tree->root = NULL;

    LOG_MSG("[ART] Tree destroyed. Recursion(status=0x%X): freed leaves=%lu, nodes=%lu; "
        "iterative_fallback(leaves=%lu, nodes=%lu)\n",
        st, leaf_count, node_count, forced_leaves, forced_nodes);

    return rc;
}

/** SEARCH Functions */
ULONG art_search(_In_ CONST ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key)
{
    if (!tree || !unicode_key) {
        return POLICY_NONE;
    }

    if (!tree->root || tree->size == 0) {
        LOG_MSG("[ART] Search on empty tree\n");
        return POLICY_NONE;
    }

    USHORT key_length = 0;
    PUCHAR key = unicode_to_utf8(unicode_key, &key_length);
    if (!key) {
        LOG_MSG("[ART] Failed to convert Unicode key\n");
        return POLICY_NONE;
    }

    if (key_length == 0) {
        LOG_MSG("[ART] Empty key after conversion\n");
        destroy_utf8_key(key);
        return POLICY_NONE;
    }

#if defined(MAX_KEY_LENGTH)
    if (key_length > MAX_KEY_LENGTH) {                // defensive: symmetry with insert/delete
        LOG_MSG("[ART] Key length %u exceeds MAX_KEY_LENGTH %u\n", key_length, MAX_KEY_LENGTH);
        destroy_utf8_key(key);
        return POLICY_NONE;
    }
#endif

    ULONG access_right = POLICY_NONE;
    ART_NODE* node = tree->root;
    USHORT depth = 0;
    USHORT search_depth = 0;

    while (node && search_depth < MAX_RECURSION_DEPTH) {
        search_depth++;

        // Leaf fast-path
        if (IS_LEAF(node)) {
            ART_LEAF* leaf = LEAF_RAW(node);
            if (leaf && leaf_matches(leaf, key, key_length)) {
                access_right = leaf->value;
            }
            break;
        }

        // Compare compressed prefix (long-prefix handled inside prefix_compare)
        if (node->prefix_length > 0) {
            if (depth >= key_length) break;

            USHORT matched = 0;
            if (!prefix_compare(node, key, key_length, depth, NULL, &matched)) {
                // mismatch or key shorter than full logical prefix
                break;
            }

            if ((USHORT)(depth + node->prefix_length) < depth) {
                // overflow guard
                break;
            }
            depth += node->prefix_length;
        }

        // If key ends at this node, look for terminator edge (0x00) leaf
        if (depth == key_length) {
            ART_NODE** term = find_child(node, 0);
            if (term && *term && IS_LEAF(*term)) {
                ART_LEAF* tleaf = LEAF_RAW(*term);
                if (tleaf && leaf_matches(tleaf, key, key_length)) {
                    access_right = tleaf->value;
                }
            }
            break;
        }

        // Descend via next edge byte
        ART_NODE** child = find_child(node, key[depth]);
        if (!child || !*child) break;

        node = *child;
        depth++;
    }

    destroy_utf8_key(key);
    return access_right;
}

#if DEBUG
static BOOLEAN verify_node(const ART_NODE* n, BOOLEAN deep) {
    if (!n) return TRUE;

    if (IS_LEAF(n)) return TRUE;

    // Common header checks
    if (n->prefix_length == 0xFFFF) return FALSE; // example poison check
    if (n->num_of_child == 0 && n != g_art_tree.root) return TRUE; // allowed if transient

    switch (n->type) {
    case NODE4: {
        const ART_NODE4* p = (const ART_NODE4*)n;
        USHORT cnt = min(n->num_of_child, 4);
        for (USHORT i = 0; i < cnt; ++i) {
            if (!p->children[i]) return FALSE;
            if (i + 1 < cnt && !(p->keys[i] < p->keys[i + 1])) return FALSE;
            if (deep && !verify_node(p->children[i], deep)) return FALSE;
        }
        for (USHORT i = cnt; i < 4; ++i) {
            if (p->children[i]) return FALSE;
        }
        break;
    }
    case NODE16: {
        const ART_NODE16* p = (const ART_NODE16*)n;
        USHORT cnt = min(n->num_of_child, 16);
        for (USHORT i = 0; i < cnt; ++i) {
            if (!p->children[i]) return FALSE;
            if (i + 1 < cnt && !(p->keys[i] < p->keys[i + 1])) return FALSE;
            if (deep && !verify_node(p->children[i], deep)) return FALSE;
        }
        break;
    }
    case NODE48: {
        const ART_NODE48* p = (const ART_NODE48*)n;
        USHORT survivors = 0;
        for (int k = 0; k < 256; ++k) {
            UCHAR m = p->child_index[k];
            if (m == 0) continue;
            if (m < 1 || m > 48) return FALSE;
            ART_NODE* ch = p->children[m - 1];
            if (!ch) return FALSE;
            if (deep && !verify_node(ch, deep)) return FALSE;
            survivors++;
        }
        if (survivors != n->num_of_child) return FALSE;
        break;
    }
    case NODE256: {
        const ART_NODE256* p = (const ART_NODE256*)n;
        USHORT survivors = 0;
        for (int k = 0; k < 256; ++k) {
            if (p->children[k]) {
                if (deep && !verify_node(p->children[k], deep)) return FALSE;
                survivors++;
            }
        }
        if (survivors != n->num_of_child) return FALSE;
        break;
    }
    default:
        return FALSE;
    }
    return TRUE;
}
#endif

