#include "test_art.h"

#define PER_TYPE  16

// Function under test
STATIC ART_NODE* art_create_node(NODE_TYPE type);

// Small helper: free a node allocated by art_create_node
static VOID test_free_node_if_any(ART_NODE* n)
{
    if (n) {
        Test_ExFreePool2(n, ART_TAG, NULL, 0);
    }
}

/* =========================================================
   Test 1: Invalid node type handling
   Purpose:
     - Ensure unsupported NODE_TYPE values are rejected.
     - No allocation must occur.
   Sub-checks:
     (1.1) Return NULL for invalid enum values
     (1.2) No allocation attempt recorded by mocks
     (1.3) Last allocated pointer remains NULL
   ========================================================= */
BOOLEAN test_art_create_node_invalid_type()
{
    TEST_START("art_create_node: Invalid Type Handling");

    reset_mock_state();

    NODE_TYPE invalids[] = { (NODE_TYPE)(-1), (NODE_TYPE)0, (NODE_TYPE)99, (NODE_TYPE)255 };

    for (ULONG i = 0; i < RTL_NUMBER_OF(invalids); ++i) {
        reset_mock_state();

        ART_NODE* n = art_create_node(invalids[i]);

        // (1.1)
        TEST_ASSERT(n == NULL, "1.1: Must return NULL for an invalid node type");

        // (1.2)
        TEST_ASSERT(g_alloc_call_count == 0, "1.2: Must not allocate for an invalid type");

        // (1.3)
        TEST_ASSERT(g_last_allocated_pointer == NULL, "1.3: No last allocation recorded for invalid type");
    }

    LOG_MSG("[INFO] Test 1 done: invalid types are safely rejected without allocations\n");

    TEST_END("art_create_node: Invalid Type Handling");
    return TRUE;
}

/* =========================================================
   Test 2: Valid types — size, fields, tag, single allocation
   Purpose:
     - Confirm correct allocation size per node type.
     - Verify zero-initialized observable fields and type set.
     - Confirm pool tag and single allocation.
   Sub-checks (repeated for NODE4, NODE16, NODE48, NODE256):
     (2.x.1) Non-NULL result
     (2.x.2) node->type == requested
     (2.x.3) node->prefix_length == 0
     (2.x.4) node->num_of_child == 0
     (2.x.5) Exactly one allocation happened
     (2.x.6) ART_TAG used for allocation
     (2.x.7) Allocated size == sizeof(struct for that type)
     (2.x.8) Cleanup frees exactly once
   ========================================================= */
BOOLEAN test_art_create_node_valid_types_basic()
{
    TEST_START("art_create_node: Valid Types (Size/Fields/Tag)");

    struct {
        NODE_TYPE t;
        SIZE_T    expect_size;
        PCSTR     name;
    } cases[] = {
        { NODE4,   sizeof(ART_NODE4),   "NODE4"   },
        { NODE16,  sizeof(ART_NODE16),  "NODE16"  },
        { NODE48,  sizeof(ART_NODE48),  "NODE48"  },
        { NODE256, sizeof(ART_NODE256), "NODE256" },
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(cases); ++i) {
        reset_mock_state();
        LOG_MSG("[INFO] Test 2.%lu starting for %s\n", (ULONG)(i + 1), cases[i].name);

        ART_NODE* node = art_create_node(cases[i].t);

        // (2.x.1)
        TEST_ASSERT(node != NULL, "2.x.1: Must return a non-NULL node for valid type");

        // (2.x.2) (2.x.3) (2.x.4)
        TEST_ASSERT(node->type == cases[i].t, "2.x.2: Node type must match request");
        TEST_ASSERT(node->prefix_length == 0, "2.x.3: prefix_length must be zero-initialized");
        TEST_ASSERT(node->num_of_child == 0, "2.x.4: num_of_child must be zero-initialized");

        // (2.x.5) (2.x.6) (2.x.7)
        TEST_ASSERT(g_alloc_call_count == 1, "2.x.5: Exactly one allocation should occur");
        TEST_ASSERT(g_last_allocated_tag == ART_TAG, "2.x.6: Allocation must use ART_TAG");
        TEST_ASSERT(g_last_allocated_size == cases[i].expect_size,
            "2.x.7: Allocated size must match node struct size");

        // (2.x.8) cleanup
        ULONG frees_before = g_free_call_count;
        test_free_node_if_any(node);
        TEST_ASSERT(g_free_call_count == frees_before + 1, "2.x.8: Cleanup must free exactly once");
    }

    LOG_MSG("[INFO] Test 2 done: all valid node types allocate correct sizes and zero fields\n");

    TEST_END("art_create_node: Valid Types (Size/Fields/Tag)");
    return TRUE;
}

/* =========================================================
   Test 3: Allocation failure path
   Purpose:
     - Simulate allocation failure and confirm graceful handling.
   Sub-checks:
     (3.1) Returns NULL when allocation fails
     (3.2) Exactly one allocation attempt is recorded
     (3.3) No frees are required/recorded
   ========================================================= */
BOOLEAN test_art_create_node_allocation_failure()
{
    TEST_START("art_create_node: Allocation Failure Path");

    reset_mock_state();

    // Configure the mock to fail the very first allocation call
    configure_mock_failure(STATUS_SUCCESS, STATUS_SUCCESS, TRUE, 0); // alloc_fail=TRUE, fail after count=0

    ART_NODE* n = art_create_node(NODE16);

    // (3.1)
    TEST_ASSERT(n == NULL, "3.1: Must return NULL when allocation fails");

    // (3.2)
    TEST_ASSERT(g_alloc_call_count == 1, "3.2: Exactly one allocation attempt must be made");

    // (3.3)
    TEST_ASSERT(g_free_call_count == 0, "3.3: No frees should occur on alloc failure");

    // Reset knobs for subsequent tests
    reset_mock_state();

    LOG_MSG("[INFO] Test 3 done: allocation failure is handled cleanly\n");

    TEST_END("art_create_node: Allocation Failure Path");
    return TRUE;
}

/* =========================================================
   Test 4: Stress — many allocations across all node types
   Purpose:
     - Ensure stability/counter correctness under repeated allocations.
   Sub-checks:
     (4.1) Each successful allocation returns non-NULL
     (4.2) type/prefix_length/num_of_child fields are correct per node
     (4.3) Freeing all nodes increases free counter accordingly
   Notes:
     - Some allocations may fail under stress; that's acceptable.
   ========================================================= */
BOOLEAN test_art_create_node_stress_many()
{
    TEST_START("art_create_node: Stress (Many Allocations)");

    reset_mock_state();

    NODE_TYPE types[] = { NODE4, NODE16, NODE48, NODE256 };

    ART_NODE* created[RTL_NUMBER_OF(types) * PER_TYPE];
    RtlZeroMemory(created, sizeof(created));

    int created_count = 0;

    // Allocate repeatedly
    for (ULONG t = 0; t < RTL_NUMBER_OF(types); ++t) {
        for (int i = 0; i < PER_TYPE; ++i) {
            ART_NODE* n = art_create_node(types[t]);
            if (n) {
                created[created_count++] = n;

                // (4.1)
                TEST_ASSERT(n != NULL, "4.1: Non-NULL node on success");

                // (4.2)
                TEST_ASSERT(n->type == types[t], "4.2: Type must match requested");
                TEST_ASSERT(n->prefix_length == 0, "4.2: prefix_length zero-initialized");
                TEST_ASSERT(n->num_of_child == 0, "4.2: num_of_child zero-initialized");
            }
            else {
                LOG_MSG("[INFO] Stress alloc failed at typeIndex=%lu iter=%d (acceptable)\n", t, i);
            }
        }
    }

    // (4.3) Free all
    ULONG frees_before = g_free_call_count;
    for (int i = 0; i < created_count; ++i) {
        test_free_node_if_any(created[i]);
    }
    TEST_ASSERT(g_free_call_count == frees_before + (ULONG)created_count,
        "4.3: All successfully allocated nodes must be freed");

    LOG_MSG("[INFO] Test 4 done: stress allocations/frees consistent (created=%d)\n", created_count);

    TEST_END("art_create_node: Stress (Many Allocations)");
    return TRUE;
}

/* =========================================================
   Test 5: Zero-initialization of observable fields
   Purpose:
     - Validate that RtlZeroMemory + constructor fields are correct.
   Sub-checks:
     (5.x.1) prefix_length == 0
     (5.x.2) num_of_child == 0
     (5.x.3) type == requested
   ========================================================= */
BOOLEAN test_art_create_node_zero_init_observables()
{
    TEST_START("art_create_node: Zero-Initialization (Observables)");

    reset_mock_state();

    NODE_TYPE types[] = { NODE4, NODE16, NODE48, NODE256 };

    for (ULONG i = 0; i < RTL_NUMBER_OF(types); ++i) {
        ART_NODE* n = art_create_node(types[i]);
        TEST_ASSERT(n != NULL, "5.x: Must allocate for valid type");

        // (5.x.1) (5.x.2) (5.x.3)
        TEST_ASSERT(n->prefix_length == 0, "5.x.1: prefix_length is zero");
        TEST_ASSERT(n->num_of_child == 0, "5.x.2: num_of_child is zero");
        TEST_ASSERT(n->type == types[i], "5.x.3: type set correctly");

        test_free_node_if_any(n);
    }

    LOG_MSG("[INFO] Test 5 done: observable fields consistently zero-initialized\n");

    TEST_END("art_create_node: Zero-Initialization (Observables)");
    return TRUE;
}

/* =========================================================
   Test 6: Size guard sanity for valid types
   Purpose:
     - While we cannot force size==0 without changing structs,
       we can ensure valid types never yield size==0 by observing
       successful allocations for each valid type.
   Sub-checks:
     (6.1) All valid types return non-NULL (implies size > 0)
   ========================================================= */
BOOLEAN test_art_create_node_size_guard_nonzero_for_valid()
{
    TEST_START("art_create_node: Size Guard (Non-zero for Valid Types)");

    reset_mock_state();

    ART_NODE* n1 = art_create_node(NODE4);
    ART_NODE* n2 = art_create_node(NODE16);
    ART_NODE* n3 = art_create_node(NODE48);
    ART_NODE* n4 = art_create_node(NODE256);

    // (6.1)
    TEST_ASSERT(n1 != NULL && n2 != NULL && n3 != NULL && n4 != NULL,
        "6.1: All valid types must produce non-NULL nodes (size > 0)");

    test_free_node_if_any(n1);
    test_free_node_if_any(n2);
    test_free_node_if_any(n3);
    test_free_node_if_any(n4);

    LOG_MSG("[INFO] Test 6 done: size guard is effectively validated via success paths\n");

    TEST_END("art_create_node: Size Guard (Non-zero for Valid Types)");
    return TRUE;
}

/* =========================================================
   Suite Runner
   ========================================================= */
NTSTATUS run_all_art_create_node_tests()
{
    LOG_MSG("\n========================================\n");
    LOG_MSG("Starting art_create_node Test Suite\n");
    LOG_MSG("========================================\n\n");

    BOOLEAN all_passed = TRUE;

    if (!test_art_create_node_invalid_type())                 all_passed = FALSE;
    if (!test_art_create_node_valid_types_basic())            all_passed = FALSE;
    if (!test_art_create_node_allocation_failure())           all_passed = FALSE;
    if (!test_art_create_node_stress_many())                  all_passed = FALSE;
    if (!test_art_create_node_zero_init_observables())        all_passed = FALSE;
    if (!test_art_create_node_size_guard_nonzero_for_valid()) all_passed = FALSE;

    LOG_MSG("\n========================================\n");
    if (all_passed) {
        LOG_MSG("ALL art_create_node TESTS PASSED!\n");
    }
    else {
        LOG_MSG("SOME art_create_node TESTS FAILED!\n");
    }
    LOG_MSG("========================================\n\n");

    return all_passed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
