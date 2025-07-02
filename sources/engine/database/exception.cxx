#include <engine/database/exception.hxx>

namespace engine::database::exception
{
    Initialize::Initialize(const std::string &p_message)
        : m_error_message(p_message)
    {
    }
    const char *Initialize::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::database::sqlite3::exception