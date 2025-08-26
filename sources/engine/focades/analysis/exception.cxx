#include <engine/focades/analysis/exception.hxx>

namespace engine::focades::analysis::exception
{
    Scan::Scan(const std::string &p_message)
        : error_message_(p_message)
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
} // namespace engine::exception
