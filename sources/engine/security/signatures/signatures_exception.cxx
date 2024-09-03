#include <engine/security/signatures/signatures_exception.hxx>

namespace Security
{
namespace SignaturesException
{
CompilerSig::CompilerSig(const std::string &p_message)
    : BaseException(p_message)
{
}

LexerToken::LexerToken(const std::string &p_message) : BaseException(p_message)
{
}

IncludeSig::IncludeSig(const std::string &p_message)
    : BaseException(p_message)
{
}
} // namespace SignaturesException
} // namespace Security