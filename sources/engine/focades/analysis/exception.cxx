#include <engine/focades/analysis/exception.hxx>

namespace engine::focades::analysis::exception
{
    Scan::Scan(const std::string &p_message)
        : m_error_message(p_message)
    {
    }

    const char *Scan::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Load::Load(const std::string &p_message) : m_error_message(p_message)
    {
    }

    const char *Load::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::exception
