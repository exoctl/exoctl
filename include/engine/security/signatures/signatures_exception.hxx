#pragma once

#include <engine/exception.hxx>

namespace Security
{
namespace SignaturesException
{
class CompilerSig : public Exception::BaseException
{
  public:
    explicit CompilerSig(const std::string &);
};

class LexerToken : public Exception::BaseException
{
  public:
    explicit LexerToken(const std::string &);
};

class IncludeSig : public Exception::BaseException
{
  public:
    explicit IncludeSig(const std::string &);
};
} // namespace SignaturesException
} // namespace Security