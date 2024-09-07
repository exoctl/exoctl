#pragma once

#include <exception>
#include <string>

namespace Exception
{
class ExceptionBase : public std::exception
{
  private:
    const std::string m_error_message;

  protected:
    explicit ExceptionBase(const std::string &message);

  public:
    virtual const char *what() const noexcept override;
};
} // namespace Exception