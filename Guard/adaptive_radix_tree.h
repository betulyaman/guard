#ifndef ADAPTIVE_RADIX_TREE_H
#define ADAPTIVE_RADIX_TREE_H
#include <fltKernel.h>

#define MAX_PREFIX_LENGTH 18 // \\device\\harddiskX\\

#define POLICY_MASK_READ    FILE_GENERIC_READ
#define POLICY_MASK_WRITE   FILE_GENERIC_WRITE
#define POLICY_MASK_EXECUTE FILE_GENERIC_EXECUTE
#define POLICY_MASK_ALL     FILE_ALL_ACCESS

typedef enum {
    NODE4,
    NODE16,
    NODE48,
    NODE256
} NODE_TYPE;

typedef struct _ART_NODE {
    NODE_TYPE type;
    BOOLEAN is_end;
    USHORT num_of_child;
    ACCESS_MASK access_rights;

    UCHAR prefix[MAX_PREFIX_LENGTH];
    USHORT prefix_length;
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
    UCHAR child_index[256];
    ART_NODE* children[48];
} ART_NODE48;

typedef struct _ART_NODE256 {
    ART_NODE base;
    ART_NODE* children[256];
} ART_NODE256;

extern ART_NODE* g_art_root;

ART_NODE* art_create_node(NODE_TYPE type);
BOOLEAN art_insert(ART_NODE** root_ref, PCUNICODE_STRING unicode_path, ACCESS_MASK access_mask);
BOOLEAN art_insert_child(ART_NODE** node_ref, UCHAR path_byte, ART_NODE* child);
BOOLEAN art_search(ART_NODE* root, PCUNICODE_STRING unicode_path, ACCESS_MASK* out_access_rights);
ART_NODE* art_find_child_prefix(ART_NODE* node, PCUCHAR path_bytes, USHORT path_length, USHORT* path_cursor);
VOID art_free_node(ART_NODE* node);

NTSTATUS policy_initialize();

#endif // ADAPTIVE_RADIX_TREE_H