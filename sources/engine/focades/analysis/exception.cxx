#include <engine/focades/analysis/exception.hxx>

namespace engine::focades::analysis::exception
{
    Scan::Scan(const std::string &p_message) : error_message_(p_message)
    {
    }

    const char *Scan::what() const noexcept
    {
        return error_message_.c_str();
    }

    Load::Load(const std::string &p_message) : error_message_(p_message)
    {
    }

    const char *Load::what() const noexcept
    {
        return error_message_.c_str();
    }

    TagExists::TagExists(const std::string &p_message)
        : error_message_(p_message)
    {
    }

    const char *TagExists::what() const noexcept
    {
        return error_message_.c_str();
    }

    FamilyExists::FamilyExists(const std::string &p_message)
        : error_message_(p_message)
    {
    }

    const char *FamilyExists::what() const noexcept
    {
        return error_message_.c_str();
    }

    FamilyNotFound::FamilyNotFound(const std::string &p_message)
        : error_message_(p_message)
    {
    }

    const char *FamilyNotFound::what() const noexcept
    {
        return error_message_.c_str();
    }

    TagNotFound::TagNotFound(const std::string &p_message)
        : error_message_(p_message)
    {
    }

    const char *TagNotFound::what() const noexcept
    {
        return error_message_.c_str();
    }

} // namespace engine::focades::analysis::exception
