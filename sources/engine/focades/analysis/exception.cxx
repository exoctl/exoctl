#include <engine/focades/analysis/exception.hxx>

namespace engine::focades::analysis::exception
{
    EnqueueScan::EnqueueScan(const std::string &p_message)
        : m_error_message(p_message)
    {
    }

    const char *EnqueueScan::what() const noexcept
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
