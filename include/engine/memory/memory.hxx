#pragma once

#include <cstddef>
#include <sys/mman.h>

// clang-format off
#define IS_NULL(ptr) (ptr == nullptr)
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define ALIGN_ADDRESS(addr) ((void *) ((size_t) (addr) & ~(PAGE_SIZE - 1)))
// clang-format on

namespace engine::memory
{
    class Memory
    {
      public:
        Memory();
        ~Memory() = default;

        static const void protect(void *, const size_t, const unsigned int);
        static const int fd(const char *, const unsigned int);
        static void ftruncate(const int, const size_t);
        static void write(const int, const char *, const size_t);
        static void close(const int);
    };
} // namespace engine::memory
