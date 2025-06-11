#ifndef ADAPTIVE_RADIX_TREE_H
#define ADAPTIVE_RADIX_TREE_H

#include <fltKernel.h>

#define MASK_READ_ONLY   0b00000100
#define MASK_READ_WRITE  0b00000110
#define MASK_FULL_ACCESS 0b00000001

typedef enum {
    NODE4,
    NODE16,
    NODE48,
    NODE256
} NODE_TYPE;

typedef struct S_ART_NODE {
    NODE_TYPE type;
    BOOLEAN is_end;
    USHORT num_of_child;
    UINT32 access_rights;

    union {
        struct { // Node4
            UCHAR keys[4];
            struct S_ART_NODE* children[4];
        } node4;

        struct { // Node16
            UCHAR keys[16];
            struct S_ART_NODE* children[16];
        } node16;

        struct { // Node48
            UCHAR child_index[256];
            struct S_ART_NODE* children[48];
        } node48;

        struct { // Node256
            struct S_ART_NODE* children[256];
        } node256;
    } node_type;

} ART_NODE;

extern ART_NODE* g_art_root;

ART_NODE* art_create_node(NODE_TYPE type);
BOOLEAN art_insert_child(ART_NODE* node, UCHAR key_byte, ART_NODE* child, UINT32 access_mask);
ART_NODE* art_find_child(ART_NODE* node, UCHAR key_byte);
BOOLEAN art_insert(ART_NODE* root, PCUNICODE_STRING key, UINT32 access_mask);
BOOLEAN art_search(ART_NODE* root, PCUNICODE_STRING key);

NTSTATUS policy_initialize();

#endif // ADAPTIVE_RADIX_TREE_H