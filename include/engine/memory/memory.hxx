#pragma once

#include <cstddef>

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
        ~Memory();

        static const void protection(void *, const size_t, const unsigned int);
        static const int memfd(const char *, const unsigned int);
    };
} // namespace engine::memory