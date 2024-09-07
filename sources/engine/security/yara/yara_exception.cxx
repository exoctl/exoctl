#include <engine/security/yara/yara_exception.hxx>

namespace Security
{
namespace YaraException
{
CompilerRules::CompilerRules(const std::string &p_message)
    : ExceptionBase(p_message)
{
}

LoadRules::LoadRules(const std::string &p_message) : ExceptionBase(p_message) {}

Initialize::Initialize(const std::string &p_message) : ExceptionBase(p_message)
{
}

Finalize::Finalize(const std::string &p_message) : ExceptionBase(p_message) {}

} // namespace YaraException
} // namespace Security
