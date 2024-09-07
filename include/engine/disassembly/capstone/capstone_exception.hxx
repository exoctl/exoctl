#pragma once

#include <engine/exception.hxx>

namespace Disassembly
{
namespace CapstoneException
{

class Initialize : public Exception::ExceptionBase
{
  public:
    explicit Initialize(const std::string &);
};

class Finalize : public Exception::ExceptionBase
{
  public:
    explicit Finalize(const std::string &);
};

class FailedDisassembly : public Exception::ExceptionBase
{
  public:
    explicit FailedDisassembly(const std::string &);
};

} // namespace CapstoneException
} // namespace Disassembly