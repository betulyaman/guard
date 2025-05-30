#include "policy_engine.h"

#include "log.h"

TRIE_NODE* g_trie = NULL;

NTSTATUS trie_new(TRIE_NODE** node) {
	*node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TRIE_NODE), 'TRIE');
	if (!node) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return STATUS_SUCCESS;
}

NTSTATUS trie_insert(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, UINT8 access_rights) {
	if (!root || !path) {
		return STATUS_INVALID_PARAMETER;
	}

	if (path_len == 0) {
		root->end_of_path = 0;
		root->access_rights = access_rights;
		return STATUS_SUCCESS;
	}

	if ((UINT8)path->Buffer[0] < ASCII_MIN || (UINT8)path->Buffer[0] > ASCII_MAX) {
		LOG_MSG("Unsupported character in a path.");
		return STATUS_INVALID_PARAMETER;
	}

	UINT8 index = (UINT8)path->Buffer[0] - ASCII_MIN;
	if (root->children == NULL) {
		NTSTATUS status = trie_new(&root->children[index]);
		if (!NT_SUCCESS(status)) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	return trie_insert(root->children[index], path + 1, path_len - 1, access_rights);
}

BOOLEAN trie_search(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, TRIE_NODE** result) {
	if (!root || !path) {
		return FALSE;
	}

	if (path_len == 0) {
		if (root->end_of_path) {
			*result = root;
			return TRUE;
		}
		else {
			return FALSE;
		}
	}

	if ((UINT8)path->Buffer[0] < ASCII_MIN || (UINT8)path->Buffer[0] > ASCII_MAX) {
		LOG_MSG("Unsupported character in a path.");
		*result = NULL;
		return FALSE;
	}


	UINT8 index = (UINT8)path->Buffer[0] - ASCII_MIN;
	if (root->children[index] == NULL) {
		*result = NULL;
		return FALSE;
	}

	return trie_search(root->children[index], path + 1, path_len - 1, result);
}

NTSTATUS trie_delete(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len) {
	if (!root || !path) {
		return STATUS_INVALID_PARAMETER;
	}

	if (path_len == 0) {
		if (!root->end_of_path) {
			LOG_MSG(" Path doesn’t exist!");
			return STATUS_INVALID_PARAMETER;
		}

		root->end_of_path = FALSE;
		root->access_rights = 0;
		for (INT i = 0; i < CHARSET_SIZE; ++i) {
			if (root->children[i]) {
				LOG_MSG("Clean children of the node before delete it!");
				return STATUS_UNSUCCESSFUL;
			}
		}

		return STATUS_SUCCESS;
	}

	if ((UINT8)path->Buffer[0] < ASCII_MIN || (UINT8)path->Buffer[0] > ASCII_MAX) {
		LOG_MSG("Unsupported character in a path.");
		return STATUS_INVALID_PARAMETER;
	}

	UINT8 index = (UINT8)path->Buffer[0];
	NTSTATUS should_delete_child = trie_delete(root->children[index], path + 1, path_len - 1);

	if (NT_SUCCESS(should_delete_child)) {
		ExFreePoolWithTag(root->children[index], 'TRIE');
		root->children[index] = NULL;

		if (!root->end_of_path) {
			for (INT i = 0; i < CHARSET_SIZE; ++i) {
				if (root->children[i]) {
					return STATUS_UNSUCCESSFUL; // it has child nodes.
				}
			}
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

VOID trie_free(TRIE_NODE* trie) {
	if (trie) {
		for (INT i = 0; i < CHARSET_SIZE; ++i) {
			if (trie->children[i]) {
				trie_free(trie->children[i]);
			}
		}
		ExFreePoolWithTag(trie, 'TRIE');
	}
}

NTSTATUS trie_update_access(TRIE_NODE* root, CONST UNICODE_STRING* path, UINT8 path_len, UINT8 new_access_rights) {
	if (!root || !path) {
		return STATUS_INVALID_PARAMETER;
	}

	if (path_len == 0) {
		if (root->end_of_path) {
			root->access_rights = new_access_rights;
			return STATUS_SUCCESS;
		}
		else {
			return STATUS_INVALID_PARAMETER;
		}
	}

	TRIE_NODE* result = NULL;
	BOOLEAN is_exist = trie_search(root, path, path_len, &result);
	if (is_exist && result->end_of_path) {
		result->access_rights = new_access_rights;
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}
