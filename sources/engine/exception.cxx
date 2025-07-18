#include <engine/exception.hxx>

namespace engine::exception
{
    Run::Run(const std::string &p_message) : m_error_message(p_message)
    {
    }

    const char *Run::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::exception
