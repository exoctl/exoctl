#pragma once

#include <exception>
#include <string>

#define TRY_BEGIN()                                                            \
    try                                                                        \
    {

#define CATCH(exception_type, action)                                          \
    catch (const exception_type &e) { action; }

#define TRY_END() }

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