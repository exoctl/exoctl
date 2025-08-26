#include <engine/parser/json/exception.hxx>

namespace engine::parser::json::exception
{
    Add::Add(const std::string &p_message) : error_message_(p_message)
    {
    }

    const char *Add::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::parser::json::exception
