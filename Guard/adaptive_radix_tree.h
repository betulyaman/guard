#ifndef ADAPTIVE_RADIX_TREE_H
#define ADAPTIVE_RADIX_TREE_H

#include <fltKernel.h>

#define MAX_PREFIX_LENGTH 23 // \\device\\harddiskvolumeX\\

// Policy mask definitions for access control integration
#define POLICY_NONE                 0
#define POLICY_MASK_READ            FILE_GENERIC_READ
#define POLICY_MASK_WRITE           FILE_GENERIC_WRITE
#define POLICY_MASK_EXECUTE         FILE_GENERIC_EXECUTE
#define POLICY_MASK_ALL_ACCESS      FILE_ALL_ACCESS
#define POLICY_MASK_ALL_BUT_DELETE  (FILE_ALL_ACCESS & ~DELETE)

//#define POLICY_MASK_READ            0x00120089
//#define POLICY_MASK_WRITE           0x00120116
//#define POLICY_MASK_EXECUTE         0x001200A0
//#define POLICY_MASK_ALL_ACCESS      0x001F01FF
//#define POLICY_MASK_ALL_BUT_DELETE  0x001E01FF

typedef enum {
    NODE4 = 1,
    NODE16,
    NODE48,
    NODE256
} NODE_TYPE;

// Callback type used for ART iteration functions
typedef INT(*art_callback)(
    VOID* data,       // User-defined callback data
    CONST PUCHAR key, // Key of the current leaf
    UINT32 key_len,   // Length of the key
    ULONG value       // Stored value in the leaf
    );

typedef struct _ART_NODE {
    NODE_TYPE type;
    USHORT num_of_child;
    USHORT prefix_length;
    UCHAR prefix[MAX_PREFIX_LENGTH];
} ART_NODE;

typedef struct _ART_NODE4 {
    ART_NODE base;
    UCHAR keys[4];
    ART_NODE* children[4];
} ART_NODE4;

typedef struct _ART_NODE16 {
    ART_NODE base;
    UCHAR keys[16];
    ART_NODE* children[16];
} ART_NODE16;

typedef struct _ART_NODE48 {
    ART_NODE base;
    UCHAR child_index[256]; // Maps keys to children indices
    ART_NODE* children[48];
} ART_NODE48;

typedef struct _ART_NODE256 {
    ART_NODE base;
    ART_NODE* children[256]; // Direct 1:1 mapping
} ART_NODE256;

#pragma warning(push)
#pragma warning(disable : 4200) // Allow zero-sized array for flexible array member
typedef struct _ART_LEAF {
    ULONG value;
    USHORT key_length;
    UCHAR key[]; // arbitrary size, as they include the key
} ART_LEAF;
#pragma warning(pop)

typedef struct _ART_TREE {
    ART_NODE* root;
    UINT64 size;
} ART_TREE;

// Global ART tree used for system-wide policy tracking
extern ART_TREE g_art_tree;

/** Initializes an ART tree */
int art_init_tree(ART_TREE* tree);

/**  Destroys an ART tree */
int art_destroy_tree(ART_TREE* tree);

/**
 * Inserts a new value into the art tree. 
 * Returns:
 * - NULL if the item was newly inserted, 
 * - otherwise the old value pointer is returned.
 */
ULONG art_insert(ART_TREE* tree, PCUNICODE_STRING key, ULONG value);

/**
 * Inserts a new value into the art tree (not replacing)
 * Returns:
 * - NULL if the item was newly inserted, 
 * - otherwise the old value pointer is returned.
 */
ULONG art_insert_no_replace(ART_TREE* tree, PCUNICODE_STRING unicode_key, ULONG value);

/**
 * Deletes a value from the ART tree.
 * Returns:
 * - POLICY_INVALID_ACCESS if the item was not found, 
 * - otherwise the access right is returned.
 */
ULONG art_delete(ART_TREE* tree, PCUNICODE_STRING unicode_key);

/**
 * Searches for a value in the ART tree.
 * Returns:
 * - POLICY_INVALID_ACCESS if the item was not found, 
 * - otherwise the access right is returned.
 */
ULONG art_search(const ART_TREE* tree, PCUNICODE_STRING key);

/** Returns the minimum valued leaf or NULL. */
ART_LEAF* art_minimum(ART_TREE* t);

/** Returns the maximum valued leaf or NULL. */
ART_LEAF* art_maximum(ART_TREE* t);

/**
 * Iterates through the entries pairs in the map, invoking a callback for each. 
 * The call back gets a key, value for each and returns an integer stop value.
 * If the callback returns non-zero, then the iteration stops.
 * Returns 0 on success, or the return of the callback.
 */
int art_iter(ART_TREE* tree, art_callback callback, VOID* data);

/**
 * Iterates through the entries pairs in the map, invoking a callback for each
 * that matches a given prefix. The call back gets a key, value for each and
 * returns an integer stop value. If the callback returns non-zero, then the iteration stops.
 * Returns 0 on success, or the return of the callback.
 */
int art_iter_prefix(ART_TREE* tree, CONST PUCHAR key, USHORT key_length, art_callback callback, VOID* data);

void print(ART_NODE* node, USHORT depth);

#endif // ADAPTIVE_RADIX_TREE_H