#include <engine/bridge/exception.hxx>

namespace engine::server::exception
{
    Abort::Abort(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Abort::what() const noexcept
    {
        return m_error_message.c_str();
    }

    ParcialAbort::ParcialAbort(const std::string &p_message)
        : m_error_message(p_message)
    {
    }
    const char *ParcialAbort::what() const noexcept
    {
        return m_error_message.c_str();
    }

} // namespace engine::server::exception
