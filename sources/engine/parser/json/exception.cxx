#include <engine/parser/json/exception.hxx>

namespace engine::parser::json::exception
{
    Add::Add(const std::string &p_message) : m_error_message(p_message)
    {
    }

    const char *Add::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::parser::json::exception
