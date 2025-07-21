#include "minifilter.h"

#ifndef GUARD_TEST_ADAPTIVE_RADIX_TREE_H
#define GUARD_TEST_ADAPTIVE_RADIX_TREE_H


#include <fltKernel.h>

#define TEST_TAG 'tesT'

#define TEST(condition, msg, ...) \
    do { \
        if (condition) { \
            DbgPrint("[SUCCESS] " msg "\n\r" __VA_OPT__(,) __VA_ARGS__); \
        } else { \
            DbgPrint("[FAILED] " msg "\n\r" __VA_OPT__(,) __VA_ARGS__); \
        } \
    } while (0)

VOID TEST_RUN();

#endif