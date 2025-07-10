#include <cstdint>

namespace engine::memory::record
{
    typedef struct Segment {
        uint64_t start;
        uint64_t end;
        const char *name;
        int type;
        int permissions;
    } Segment;
} // namespace engine::memory::record