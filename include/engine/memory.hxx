#pragma once

// clang-format off
#define IS_NULL(ptr) (ptr == nullptr)
#define ALIGN_ADDRESS(addr) ((void *) ((size_t) (addr) & ~(sysconf(_SC_PAGE_SIZE) - 1)));