#include <cstring>
#include <engine/memory/exception.hxx>
#include <engine/memory/memory.hxx>
#include <link.h>
#include <unistd.h>

namespace engine::memory
{
    Memory::Memory()
    {
        Memory::update();
    }

    void Memory::update()
    {
        segments.clear();

        dl_iterate_phdr(
            [](struct dl_phdr_info *info, size_t, void *data) {
                Memory *self = static_cast<Memory *>(data);
                for (int i = 0; i < info->dlpi_phnum; i++) {
                    const auto &phdr = info->dlpi_phdr[i];
                    record::Segment segment;
                    segment.start = info->dlpi_addr + phdr.p_vaddr;
                    segment.end = segment.start + phdr.p_memsz;
                    segment.permissions = phdr.p_flags;
                    segment.type = phdr.p_type;
                    segment.name = info->dlpi_name;
                    self->segments.push_back(segment);
                }
                return 0;
            },
            this);
    }

    void Memory::bind_to_lua(sol::state_view &p_lua)
    {
        p_lua.new_usertype<record::Segment>(
            "Segment",
            sol::constructors<record::Segment()>(),
            "start",
            sol::readonly(&record::Segment::start),
            "end",
            sol::readonly(&record::Segment::end),
            "name",
            sol::readonly(&record::Segment::name),
            "type",
            sol::readonly(&record::Segment::type),
            "permissions",
            sol::readonly(&record::Segment::permissions));

        p_lua.new_usertype<memory::Memory>(
            "Memory",
            sol::constructors<memory::Memory()>(),
            "protect",
            &Memory::protect,
            "fd",
            &Memory::fd,
            "ftruncate",
            &Memory::ftruncate,
            "update",
            &Memory::update,
            "write",
            &Memory::write,
            "close",
            &Memory::close,
            "segments",
            &Memory::segments);
    }

    const void Memory::protect(void *p_address,
                               const size_t p_len,
                               const unsigned int p_prot)
    {
        if (mprotect(p_address, p_len, p_prot) < 0) {
            throw exception::Protect("mprotect() failed: " +
                                     std::string(strerror(errno)));
        }
    }

    const int Memory::fd(const char *p_name, const unsigned int p_flags)
    {
        const int fd = memfd_create(p_name, p_flags);
        if (fd < 0) {
            throw exception::Fd("memfd_create() failed: " +
                                std::string(strerror(errno)));
        }
        return fd;
    }

    void Memory::ftruncate(const int p_fd, const size_t p_size)
    {
        const int ret = ::ftruncate(p_fd, p_size);
        if (ret < 0) {
            throw exception::Ftruncate("ftruncate() failed: " +
                                       std::string(strerror(errno)));
        }
    }

    void Memory::write(const int p_fd, const char *p_data, const size_t p_size)
    {
        if (::write(p_fd, p_data, p_size) < 0)
            throw exception::Write("write() failed: " +
                                   std::string(strerror(errno)));
    }

    void Memory::close(const int p_fd)
    {
        ::close(p_fd);
    }
} // namespace engine::memory
