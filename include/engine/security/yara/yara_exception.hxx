#pragma once

#include <exception>
#include <string>

namespace Security
{
namespace YaraException
{

class BaseException : public std::exception
{
  private:
    const std::string m_error_message;

  protected:
    explicit BaseException(const std::string &message);

  public:
    virtual const char *what() const noexcept override;
};

class CompilerRules : public BaseException
{
  public:
    explicit CompilerRules(const std::string &message);
};

class LoadRules : public BaseException
{
  public:
    explicit LoadRules(const std::string &message);
};

class InitializeRules : public BaseException
{
  public:
    explicit InitializeRules(const std::string &message);
};

class FinalizeRules : public BaseException
{
  public:
    explicit FinalizeRules(const std::string &message);
};

} // namespace YaraException
} // namespace Security
