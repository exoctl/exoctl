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

    Migrations::Migrations(const std::string &p_message)
        : m_error_message(p_message)
    {
    }
    const char *Migrations::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Schema::Schema(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Schema::what() const noexcept
    {
        return m_error_message.c_str();
    }

    Query::Query(const std::string &p_message) : m_error_message(p_message)
    {
    }
    const char *Query::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::database::exception