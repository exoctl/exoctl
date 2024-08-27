#pragma once

#include <exception>
#include <string>

namespace Exception
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
} // namespace Exception