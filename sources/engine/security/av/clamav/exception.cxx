#include <engine/security/av/clamav/exception.hxx>

namespace engine::security::av::clamav::exception
{

    Initialize::Initialize(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *Initialize::what() const noexcept
    {
        return error_message_.c_str();
    }

    LoadRules::LoadRules(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *LoadRules::what() const noexcept
    {
        return error_message_.c_str();
    }

    Scan::Scan(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Scan::what() const noexcept
    {
        return error_message_.c_str();
    }

    SetDbRules::SetDbRules(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *SetDbRules::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::security::av::clamav::exception
