#include <cstring>
#include <engine/memory/exception.hxx>
#include <engine/memory/memory.hxx>
#include <sys/mman.h>

namespace engine::memory
{
    Memory::Memory()
    {
    }

    Memory::~Memory()
    {
    }

    const void Memory::protection(void *p_address,
                                  const size_t p_len,
                                  const unsigned int p_prot)
    {
        if (mprotect(p_address, p_len, p_prot) < 0) {
            throw exception::Protection("mprotect() failed: " +
                                        std::string(strerror(errno)));
        }
    }

    const int Memory::memfd(const char *p_name, const unsigned int p_flags)
    {
        int fd = memfd_create(p_name, p_flags);
        if (fd < 0) {
            throw exception::Memfd("memfd_create() failed: " +
                                   std::string(strerror(errno)));
        }
        return fd;
    }
} // namespace engine::memory