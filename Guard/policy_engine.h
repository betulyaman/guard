#ifndef GUARD_POLICY_ENGINE_H
#define GUARD_POLICY_ENGINE_H

#include <ntifs.h>

#define MASK_READ_ONLY   0b00000100
#define MASK_READ_WRITE  0b00000110
#define MASK_FULL_ACCESS 0b00000001

#define ASCII_MIN 32
#define ASCII_MAX 126
#define CHARSET_SIZE (ASCII_MAX - ASCII_MIN + 1)

typedef struct S_TRIE_NODE {
    struct S_TRIE_NODE* children[CHARSET_SIZE];
    BOOLEAN end_of_path;
    UINT32 access_rights;
} TRIE_NODE;

extern TRIE_NODE* g_trie_root;

NTSTATUS trie_new(TRIE_NODE** node);
NTSTATUS trie_insert(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, UINT32 access_rights);
BOOLEAN trie_search(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, TRIE_NODE** result);
NTSTATUS trie_delete(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len);
NTSTATUS trie_update_access(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, UINT32 new_access_rights);
VOID trie_free(TRIE_NODE* trie);
NTSTATUS policy_initialize();

#endif // GUARD_POLICY_ENGINE_H

