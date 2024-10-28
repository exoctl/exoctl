#include <cstring>
#include <engine/memory/exception.hxx>
#include <engine/memory/memory.hxx>
#include <unistd.h>

namespace engine::memory
{
    Memory::Memory()
    {
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

    void Memory::write(const int p_fd, const char *p_data, const size_t p_size)
    {
        if (::write(p_fd, p_data, p_size) == -1)
            throw exception::Write("write() failed: " +
                                   std::string(strerror(errno)));
    }
} // namespace engine::memory