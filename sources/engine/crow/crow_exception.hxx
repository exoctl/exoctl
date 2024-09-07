#pragma once

#include <engine/exception.hxx>

namespace Crow
{
namespace CrowException
{
class Abort : public Exception::ExceptionBase
{
  public:
    explicit Abort(const std::string &);
};
} // namespace CrowException
} // namespace Crow