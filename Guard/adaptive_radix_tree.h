#ifndef ADAPTIVE_RADIX_TREE_H
#define ADAPTIVE_RADIX_TREE_H

#include "minifilter.h"

#include <fltKernel.h>
#include <wdm.h>

#define MAX_PREFIX_LENGTH   23   // \\device\\harddiskvolumeX
#define MAX_KEY_LENGTH      4096 // 4KB maximum key length
#define MAX_RECURSION_DEPTH 192  // Stack guard

#define IS_LEAF(x) (((uintptr_t)x & 1))
#define SET_LEAF(x) ((VOID*)((uintptr_t)x | 1))
#define LEAF_RAW(x) ((ART_LEAF*)((VOID*)((uintptr_t)x & ~1)))

#define ART_TAG 'trAd'

// Policy mask definitions for access control integration
#define POLICY_NONE                 0
#define POLICY_MASK_READ            FILE_GENERIC_READ // 0x00120089
#define POLICY_MASK_WRITE           FILE_GENERIC_WRITE // 0x00120116
#define POLICY_MASK_EXECUTE         FILE_GENERIC_EXECUTE // 0x001200A0
#define POLICY_MASK_ALL_ACCESS      FILE_ALL_ACCESS // 0x001F01FF
#define POLICY_MASK_ALL_BUT_DELETE  (FILE_ALL_ACCESS & ~DELETE) // 0x001E01FF

// English comments as you asked
#ifndef SIZE_T_MAX
#define SIZE_T_MAX ((SIZE_T)~(SIZE_T)0)   // max of SIZE_T without pulling stdint.h
#endif

#ifdef DEBUG
// Poison value to detect double-frees on leaves
#define LEAF_FREED_MAGIC ((USHORT)0xDEAD)
#endif

#ifndef ART_ENABLE_POISON_ON_FREE
#  ifdef DEBUG
#    define ART_ENABLE_POISON_ON_FREE 1
#  else
#    define ART_ENABLE_POISON_ON_FREE 0
#  endif
#endif


typedef enum { 
	NODE4 = 1, 
	NODE16, 
	NODE48, 
	NODE256
} NODE_TYPE;

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
NTSTATUS art_init_tree(ART_TREE* tree);

/**  Destroys an ART tree */
NTSTATUS art_destroy_tree(_Inout_ ART_TREE* tree);

/**
 * Inserts a new value into the art tree.
 * Returns:
 * - NULL if the item was newly inserted,
 * - otherwise the old value pointer is returned.
 */
NTSTATUS art_insert(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key, _In_ ULONG value, _Out_opt_ PULONG old_value);

/**
 * Inserts a new value into the art tree (not replacing)
 * Returns:
 * - NULL if the item was newly inserted,
 * - otherwise the old value pointer is returned.
 */
NTSTATUS art_insert_no_replace(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key, _In_ ULONG value, _Out_opt_ PULONG existing_value);

/**
 * Deletes a value from the ART tree.
 * Returns:
 * - POLICY_INVALID_ACCESS if the item was not found,
 * - otherwise the access right is returned.
 */
ULONG art_delete(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

/**
 * Deletes all keys (files, paths, or data) under a given prefix in the ART tree.
 */
NTSTATUS art_delete_subtree(_Inout_ ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

/**
 * Searches for a value in the ART tree.
 * Returns:
 * - POLICY_INVALID_ACCESS if the item was not found,
 * - otherwise the access right is returned.
 */
ULONG art_search(_In_ CONST ART_TREE* tree, _In_ PCUNICODE_STRING unicode_key);

/** Returns the minimum valued leaf or NULL. */
ART_LEAF* art_minimum(ART_TREE* t);

/** Returns the maximum valued leaf or NULL. */
ART_LEAF* art_maximum(ART_TREE* t);

#if defined(UNIT_TEST)

extern PVOID Test_ExAllocatePool2(ULONG PoolFlags, SIZE_T NumberOfBytes, ULONG Tag);
extern VOID Test_ExFreePool2(PVOID P, ULONG Tag, PCPOOL_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParametersCount);
NTSTATUS Test_RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);
NTSTATUS Test_RtlUnicodeToUTF8N(PCHAR UTF8StringDestination, ULONG UTF8StringMaxByteCount, PULONG UTF8StringActualByteCount, PCWCH UnicodeStringSource, ULONG UnicodeStringByteCount);

#define ExAllocatePool2 Test_ExAllocatePool2
#define ExFreePool2 Test_ExFreePool2
#define RtlDowncaseUnicodeString Test_RtlDowncaseUnicodeString
#define RtlUnicodeToUTF8N Test_RtlUnicodeToUTF8N

STATIC PUCHAR unicode_to_utf8(_In_ PCUNICODE_STRING unicode, _Out_ PUSHORT out_length);
STATIC VOID destroy_utf8_key(_In_opt_ PUCHAR key);
STATIC VOID free_node(_Inout_ ART_NODE** node);
STATIC VOID free_leaf(_Inout_ ART_LEAF** leaf);
STATIC ART_NODE* art_create_node(_In_ NODE_TYPE type);
STATIC BOOLEAN leaf_matches(CONST ART_LEAF* leaf, CONST PUCHAR key, SIZE_T key_length);
STATIC unsigned int ctz(UINT32 x);
STATIC ART_NODE** find_child(_In_ ART_NODE* node, _In_ UCHAR c);
STATIC NTSTATUS copy_header(_Inout_ ART_NODE* dest, _In_ ART_NODE* src);
STATIC USHORT check_prefix(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth);
STATIC ART_LEAF* minimum(CONST ART_NODE* node);
STATIC ART_LEAF* maximum(CONST ART_NODE* node);
STATIC ART_LEAF* make_leaf(CONST PUCHAR key, USHORT key_length, ULONG value);
STATIC USHORT longest_common_prefix(CONST ART_LEAF* leaf1, CONST ART_LEAF* leaf2, USHORT depth);
STATIC USHORT prefix_mismatch(_In_ CONST ART_NODE* node, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth, _In_opt_ CONST ART_LEAF* rep_leaf);
STATIC NTSTATUS add_child256(_Inout_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);
STATIC NTSTATUS add_child48(_Inout_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);
STATIC NTSTATUS add_child16(_Inout_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);
STATIC NTSTATUS add_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);
STATIC NTSTATUS add_child(_Inout_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_ PVOID child);
STATIC NTSTATUS recursive_insert(_Inout_opt_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ CONST PUCHAR key, _In_ USHORT key_length, _In_ ULONG value, _In_ USHORT depth, _Out_ PBOOLEAN old, _In_ BOOLEAN replace, _Out_ PULONG old_value);
STATIC NTSTATUS remove_child256(_In_ ART_NODE256* node, _Inout_ ART_NODE** ref, _In_ UCHAR c);
STATIC NTSTATUS remove_child48(_In_ ART_NODE48* node, _Inout_ ART_NODE** ref, _In_ UCHAR c);
STATIC NTSTATUS remove_child16(_In_ ART_NODE16* node, _Inout_ ART_NODE** ref, _In_ ART_NODE** leaf);
STATIC NTSTATUS remove_child4(_Inout_ ART_NODE4* node, _Inout_ ART_NODE** ref, _Inout_ ART_NODE** remove_slot);
STATIC NTSTATUS remove_child(_In_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_ UCHAR c, _In_opt_ ART_NODE** leaf);
STATIC ART_LEAF* recursive_delete_internal(_In_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth, _In_ USHORT recursion_depth);
STATIC ART_LEAF* recursive_delete(_In_opt_ ART_NODE* node, _Inout_ ART_NODE** ref, _In_reads_bytes_(key_length) CONST PUCHAR key, _In_ USHORT key_length, _In_ USHORT depth);
STATIC NTSTATUS recursive_delete_all_internal(_Inout_ ART_TREE* tree, _Inout_ ART_NODE** slot, _Inout_ PULONG leaf_count, _Inout_ PULONG node_count, _In_ USHORT recursion_depth);
STATIC NTSTATUS force_delete_all_iterative(_Inout_ ULONG* leaf_count, _Inout_ ULONG* node_count, _Inout_ ART_NODE** proot);

VOID art_print_tree(_In_opt_ ART_TREE* tree);
VOID art_print_subtree(_In_opt_ ART_NODE* subtree_root, _In_z_ const char* description);
BOOLEAN art_validate_tree_quick(_In_opt_ ART_TREE* tree);
#endif

#endif // ADAPTIVE_RADIX_TREE_H