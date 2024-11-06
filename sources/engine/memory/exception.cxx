#include <include/engine/memory/exception.hxx>

namespace engine::memory::exception
{
    Protect::Protect(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Protect::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Fd::Fd(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Fd::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Ftruncate::Ftruncate(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Ftruncate::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Write::Write(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Write::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::memory::exception
