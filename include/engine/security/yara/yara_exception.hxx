#pragma once

#include <engine/exception.hxx>
#include <string>

namespace Security
{
namespace YaraException
{
class CompilerRules : public Exception::BaseException
{
  public:
    explicit CompilerRules(const std::string &);
};

class LoadRules : public Exception::BaseException
{
  public:
    explicit LoadRules(const std::string &);
};

class Initialize : public Exception::BaseException
{
  public:
    explicit Initialize(const std::string &);
};

class Finalize : public Exception::BaseException
{
  public:
    explicit Finalize(const std::string &);
};

} // namespace YaraException
} // namespace Security
