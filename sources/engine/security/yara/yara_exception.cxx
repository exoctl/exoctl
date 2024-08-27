#include <engine/security/yara/yara_exception.hxx>

namespace Security
{
namespace YaraException
{

BaseException::BaseException(const std::string &message)
    : m_error_message(message)
{
}

const char *BaseException::what() const noexcept
{
    return m_error_message.c_str();
}

CompilerRules::CompilerRules(const std::string &message)
    : BaseException(message)
{
}

LoadRules::LoadRules(const std::string &message) : BaseException(message) {}

InitializeRules::InitializeRules(const std::string &message)
    : BaseException(message)
{
}

FinalizeRules::FinalizeRules(const std::string &message)
    : BaseException(message)
{
}

} // namespace YaraException
} // namespace Security
