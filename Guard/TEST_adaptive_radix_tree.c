//#include <fcntl.h>
//#include <inttypes.h>
//#include <stdio.h>
//#include <string.h>
//
//#include "TEST_adaptive_radix_tree.h"
//#include "adaptive_radix_tree.h"
//
//void test_art_init_and_destroy()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    ASSERT(t.size == 0);
//
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\words.txt", "r");
//    if (!f) {
//        perror("fopen D:\\workspace\\TEST\\libart\\tests\\words.txt");
//        ASSERT(0);
//        return;
//    }
//
//    uintptr_t line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//        ASSERT(t.size == line);
//        line++;
//    }
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert_verylong()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    unsigned char key1[300] = { 16,0,0,0,7,10,0,0,0,2,17,10,0,0,0,120,10,0,0,0,120,10,0,
//      0,0,216,10,0,0,0,202,10,0,0,0,194,10,0,0,0,224,10,0,0,0,
//      230,10,0,0,0,210,10,0,0,0,206,10,0,0,0,208,10,0,0,0,232,
//      10,0,0,0,124,10,0,0,0,124,2,16,0,0,0,2,12,185,89,44,213,
//      251,173,202,211,95,185,89,110,118,251,173,202,199,101,0,
//      8,18,182,92,236,147,171,101,150,195,112,185,218,108,246,
//      139,164,234,195,58,177,0,8,16,0,0,0,2,12,185,89,44,213,
//      251,173,202,211,95,185,89,110,118,251,173,202,199,101,0,
//      8,18,180,93,46,151,9,212,190,95,102,178,217,44,178,235,
//      29,190,218,8,16,0,0,0,2,12,185,89,44,213,251,173,202,
//      211,95,185,89,110,118,251,173,202,199,101,0,8,18,180,93,
//      46,151,9,212,190,95,102,183,219,229,214,59,125,182,71,
//      108,180,220,238,150,91,117,150,201,84,183,128,8,16,0,0,
//      0,2,12,185,89,44,213,251,173,202,211,95,185,89,110,118,
//      251,173,202,199,101,0,8,18,180,93,46,151,9,212,190,95,
//      108,176,217,47,50,219,61,134,207,97,151,88,237,246,208,
//      8,18,255,255,255,219,191,198,134,5,223,212,72,44,208,
//      250,180,14,1,0,0,8, '\0' };
//    unsigned char key2[303] = { 16,0,0,0,7,10,0,0,0,2,17,10,0,0,0,120,10,0,0,0,120,10,0,
//      0,0,216,10,0,0,0,202,10,0,0,0,194,10,0,0,0,224,10,0,0,0,
//      230,10,0,0,0,210,10,0,0,0,206,10,0,0,0,208,10,0,0,0,232,
//      10,0,0,0,124,10,0,0,0,124,2,16,0,0,0,2,12,185,89,44,213,
//      251,173,202,211,95,185,89,110,118,251,173,202,199,101,0,
//      8,18,182,92,236,147,171,101,150,195,112,185,218,108,246,
//      139,164,234,195,58,177,0,8,16,0,0,0,2,12,185,89,44,213,
//      251,173,202,211,95,185,89,110,118,251,173,202,199,101,0,
//      8,18,180,93,46,151,9,212,190,95,102,178,217,44,178,235,
//      29,190,218,8,16,0,0,0,2,12,185,89,44,213,251,173,202,
//      211,95,185,89,110,118,251,173,202,199,101,0,8,18,180,93,
//      46,151,9,212,190,95,102,183,219,229,214,59,125,182,71,
//      108,180,220,238,150,91,117,150,201,84,183,128,8,16,0,0,
//      0,3,12,185,89,44,213,251,133,178,195,105,183,87,237,150,
//      155,165,150,229,97,182,0,8,18,161,91,239,50,10,61,150,
//      223,114,179,217,64,8,12,186,219,172,150,91,53,166,221,
//      101,178,0,8,18,255,255,255,219,191,198,134,5,208,212,72,
//      44,208,250,180,14,1,0,0,8, '\0' };
//
//
//    UNICODE_STRING prefix;
//    RtlInitUnicodeString(&prefix, key1);
//    ASSERT(NULL == art_insert(&t, &prefix, (void*)key1));
//    ASSERT(NULL == art_insert(&t, &prefix, (void*)key2));
//    
//    RtlInitUnicodeString(&prefix, key2);
//    art_insert(&t, &prefix, (void*)key2);
//    ASSERT(t.size == 2);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert_search()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\words.txt", "r");
//
//    uintptr_t line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//        ASSERT(NULL == art_insert(&t, (unsigned char*)buf, len, (void*)line));
//        line++;
//    }
//
//    // Seek back to the start
//    fseek(f, 0, SEEK_SET);
//
//    // Search for each line
//    line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//
//        UNICODE_STRING unicode_str;
//        RtlInitUnicodeString(&unicode_str, buf);
//        uintptr_t val = (uintptr_t)art_search(&t, &unicode_str, len);
//        ASSERT(line == val);
//
//        line++;
//    }
//
//    // Check the minimum
//    ART_LEAF* l = art_minimum(&t);
//    ASSERT(l && strcmp((char*)l->key, "A") == 0);
//
//    // Check the maximum
//    l = art_maximum(&t);
//    ASSERT(l && strcmp((char*)l->key, "zythum") == 0);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert_delete()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\words.txt", "r");
//
//    uintptr_t line = 1, nlines;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//        UNICODE_STRING unicode_str;
//        RtlInitUnicodeString(&unicode_str, buf);
//        ASSERT(NULL == art_insert(&t, &unicode_str, (void*)line));
//        line++;
//    }
//
//    nlines = line - 1;
//
//    // Seek back to the start
//    fseek(f, 0, SEEK_SET);
//
//    // Search for each line
//    line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//
//        // Search first, ensure all entries still
//        // visible
//
//        UNICODE_STRING unicode_str;
//        RtlInitUnicodeString(&unicode_str, buf);
//        uintptr_t val = (uintptr_t)art_search(&t, &unicode_str);
//        ASSERT(line == val);
//
//        // Delete, should get lineno back
//        val = (uintptr_t)art_delete(&t, &unicode_str);
//        ASSERT(line == val);
//
//        // Check the size
//        ASSERT(t.size == nlines - line);
//        line++;
//    }
//
//    // Check the minimum and maximum
//    ASSERT(!art_minimum(&t));
//    ASSERT(!art_maximum(&t));
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert_random_delete()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\words.txt", "r");
//
//    uintptr_t line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//
//        UNICODE_STRING unicode_str;
//        RtlInitUnicodeString(&unicode_str, buf);
//        ASSERT(NULL == art_insert(&t, &unicode_str,(void*)line));
//        line++;
//    }
//
//    // Can be improved ensuring one delete on each node type
//    // A is in 48 node
//    uintptr_t lineno = 1;
//    // Search first, ensure all entries are visible
//    UNICODE_STRING unicode_str;
//    RtlInitUnicodeString(&unicode_str, L"A");
//    uintptr_t val = (uintptr_t)art_search(&t, &unicode_str);
//    ASSERT(lineno == val);
//
//    // Delete a single entry, should get lineno back
//    val = (uintptr_t)art_delete(&t, &unicode_str);
//    ASSERT(lineno == val);
//
//    // Ensure  the entry is no longer visible
//    val = (uintptr_t)art_search(&t, &unicode_str);
//    ASSERT(0 == val);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//int iter_cb(void* data, const unsigned char* key, uint32_t key_len, void* val) {
//    uint64_t* out = (uint64_t*)data;
//    uintptr_t line = (uintptr_t)val;
//    uint64_t mask = (line * (key[0] + key_len));
//    out[0]++;
//    out[1] ^= mask;
//    return 0;
//}
//
//void test_art_insert_iter()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\words.txt", "r");
//
//    uint64_t xor_mask = 0;
//    uintptr_t line = 1, nlines;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//        UNICODE_STRING unicode_str;
//        RtlInitUnicodeString(&unicode_str, buf);
//        ASSERT(NULL == art_insert(&t, &unicode_str, (void*)line));
//
//        xor_mask ^= (line * (buf[0] + len));
//        line++;
//    }
//    nlines = line - 1;
//
//    uint64_t out[] = { 0, 0 };
//    ASSERT(art_iter(&t, iter_cb, &out) == 0);
//
//    ASSERT(out[0] == nlines);
//    ASSERT(out[1] == xor_mask);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//typedef struct {
//    int count;
//    int max_count;
//    const char** expected;
//} prefix_data;
//
//static int test_prefix_cb(void* data, const unsigned char* k, uint32_t k_len, void* val) {
//    prefix_data* p = (prefix_data*)data;
//    ASSERT(p->count < p->max_count);
//    ASSERT(memcmp(k, p->expected[p->count], k_len) == 0);
//    p->count++;
//    return 0;
//}
//
//void test_art_iter_prefix()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//
//    UNICODE_STRING unicode_str;
//    RtlInitUnicodeString(&unicode_str, L"api.foo.bar");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"api.foo.baz");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"api.foe.fum");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"abc.123.456");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"api.foo.baz");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"api.foo");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    RtlInitUnicodeString(&unicode_str, L"api");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//
//    // Iterate over api
//    const char* expected[] = { "api", "api.foe.fum", "api.foo", "api.foo.bar", "api.foo.baz" };
//    prefix_data p = { 0, 5, expected };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"api", 3, test_prefix_cb, &p));
//    ASSERT(p.count == p.max_count);
//
//    // Iterate over 'a'
//    const char* expected2[] = { "abc.123.456", "api", "api.foe.fum", "api.foo", "api.foo.bar", "api.foo.baz" };
//    prefix_data p2 = { 0, 6, expected2 };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"a", 1, test_prefix_cb, &p2));
//    ASSERT(p2.count == p2.max_count);
//
//    // Check a failed iteration
//    prefix_data p3 = { 0, 0, NULL };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"b", 1, test_prefix_cb, &p3));
//    ASSERT(p3.count == 0);
//
//    // Iterate over api.
//    const char* expected4[] = { "api.foe.fum", "api.foo", "api.foo.bar", "api.foo.baz" };
//    prefix_data p4 = { 0, 4, expected4 };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"api.", 4, test_prefix_cb, &p4));
//    ASSERT(p4.count == p4.max_count);
//
//    // Iterate over api.foo.ba
//    const char* expected5[] = { "api.foo.bar" };
//    prefix_data p5 = { 0, 1, expected5 };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"api.foo.bar", 11, test_prefix_cb, &p5));
//    ASSERT(p5.count == p5.max_count);
//
//    // Check a failed iteration on api.end
//    prefix_data p6 = { 0, 0, NULL };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"api.end", 7, test_prefix_cb, &p6));
//    ASSERT(p6.count == 0);
//
//    // Iterate over empty prefix
//    prefix_data p7 = { 0, 6, expected2 };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"", 0, test_prefix_cb, &p7));
//    ASSERT(p7.count == p7.max_count);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_long_prefix()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    uintptr_t v;
//    const char* s;
//
//    UNICODE_STRING unicode_str;
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:prefix:3");
//    ASSERT(NULL == art_insert(&t, &unicode_str, NULL));
//    v = 3;
//    ASSERT(NULL == art_insert(&t, &unicode_str, (void*)v));
//
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:common:prefix:2");
//    v = 2;
//    ASSERT(NULL == art_insert(&t, &unicode_str, (void*)v));
//
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:common:prefix:1");
//    v = 1;
//    ASSERT(NULL == art_insert(&t, &unicode_str, (void*)v));
//
//    // Search for the keys
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:common:prefix:1");
//    ASSERT(1 == (uintptr_t)art_search(&t, &unicode_str));
//
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:common:prefix:2");
//    ASSERT(2 == (uintptr_t)art_search(&t, &unicode_str));
//
//    RtlInitUnicodeString(&unicode_str, L"this:key:has:a:long:prefix:3");
//    ASSERT(3 == (uintptr_t)art_search(&t, &unicode_str));
//
//
//    const char* expected[] = {
//        "this:key:has:a:long:common:prefix:1",
//        "this:key:has:a:long:common:prefix:2",
//        "this:key:has:a:long:prefix:3",
//    };
//    prefix_data p = { 0, 3, expected };
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)"this:key:has", 12, test_prefix_cb, &p));
//    ASSERT(p.count == p.max_count);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_insert_search_uuid()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    int len;
//    char buf[512];
//    FILE* f = fopen("D:\\workspace\\TEST\\libart\\tests\\uuid.txt", "r");
//
//    uintptr_t line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//        ASSERT(NULL == art_insert(&t, (unsigned char*)buf, len, (void*)line));
//        line++;
//    }
//
//    // Seek back to the start
//    fseek(f, 0, SEEK_SET);
//
//    // Search for each line
//    line = 1;
//    while (fgets(buf, sizeof buf, f)) {
//        len = (int)strlen(buf);
//        buf[len - 1] = '\0';
//
//        uintptr_t val = (uintptr_t)art_search(&t, (unsigned char*)buf, len);
//        ASSERT(line == val);
//        line++;
//    }
//
//    // Check the minimum
//    ART_LEAF* l = art_minimum(&t);
//    ASSERT(l && strcmp((char*)l->key, "00026bda-e0ea-4cda-8245-522764e9f325") == 0);
//
//    // Check the maximum
//    l = art_maximum(&t);
//    ASSERT(l && strcmp((char*)l->key, "ffffcb46-a92e-4822-82af-a7190f9c1ec5") == 0);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//void test_art_max_prefix_len_scan_prefix()
//{
//    ART_TREE t;
//    int res = art_init_tree(&t);
//    ASSERT(res == 0);
//
//    UNICODE_STRING prefix;
//    RtlInitUnicodeString(&prefix, L"foobarbaz1-test1-foo");
//    ASSERT(NULL == art_insert(&t, &prefix, NULL));
//
//    UNICODE_STRING prefix;
//    RtlInitUnicodeString(&prefix, L"foobarbaz1-test1-bar");
//    ASSERT(NULL == art_insert(&t, &prefix, NULL));
//
//    char* key3 = "foobarbaz1-test2-foo";
//    ASSERT(NULL == art_insert(&t, (unsigned char*)key3, (int)strlen(key3) + 1, NULL));
//
//    ASSERT(t.size == 3);
//
//    // Iterate over api
//    const char* expected[] = { key2, key1 };
//    prefix_data p = { 0, 2, expected };
//    char* prefix = "foobarbaz1-test1";
//    ASSERT(!art_iter_prefix(&t, (unsigned char*)prefix, (int)strlen(prefix), test_prefix_cb, &p));
//    ASSERT(p.count == p.max_count);
//
//    res = art_destroy_tree(&t);
//    ASSERT(res == 0);
//}
//
//VOID TEST_RUN() {
//    test_art_init_and_destroy();
//    test_art_insert();
//    test_art_insert_verylong();
//    test_art_insert_search();
//    test_art_insert_delete();
//    test_art_insert_random_delete();
//    test_art_insert_iter();
//    test_art_iter_prefix();
//    test_art_long_prefix();
//    test_art_insert_search_uuid();
//    test_art_max_prefix_len_scan_prefix();
//}