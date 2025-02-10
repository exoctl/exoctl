namespace engine::memory::record
{
    typedef struct Segment {
        char *start;
        char *end;
        const char *name;
        int type;
        int permissions;
    } Segment;
} // namespace engine::memory::record