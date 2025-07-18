#pragma once

#include <cstddef>
#include <engine/memory/entitys.hxx>
#include <sys/mman.h>
#include <cstdint>
#include <vector>

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

        std::vector<record::Segment> segments;
        void update_segments();
        static void protect(void *, const size_t, const unsigned int);
        [[nodiscard]] static const int fd(const char *, const unsigned int);
        static void ftruncate(const int, const size_t);
        static void write(const int, const char *, const size_t);
        static void close(const int);
    };
} // namespace engine::memory
