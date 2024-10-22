#include <include/engine/memory/exception.hxx>

namespace engine::memory::exception
{
    Protection::Protection(const std::string &p_message)
        : m_error_message(p_message)
    {
    }
    const char *Protection::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Memfd::Memfd(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Memfd::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::memory::exception