#include <engine/database/exception.hxx>

namespace engine::database::exception
{
    Initialize::Initialize(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *Initialize::what() const noexcept
    {
        return error_message_.c_str();
    }

    Migrations::Migrations(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *Migrations::what() const noexcept
    {
        return error_message_.c_str();
    }

    Schema::Schema(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Schema::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::database::exception