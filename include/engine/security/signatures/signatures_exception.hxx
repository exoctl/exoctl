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
} // namespace SignaturesException
} // namespace Security