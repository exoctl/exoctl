#include <include/engine/memory/exception.hxx>

namespace engine::memory::exception
{
    Protect::Protect(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Protect::what() const noexcept
    {
        return error_message_.c_str();
    }

    Fd::Fd(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Fd::what() const noexcept
    {
        return error_message_.c_str();
    }

    Ftruncate::Ftruncate(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *Ftruncate::what() const noexcept
    {
        return error_message_.c_str();
    }

    Write::Write(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Write::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::memory::exception
