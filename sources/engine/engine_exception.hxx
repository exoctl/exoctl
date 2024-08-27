#pragma once

#include <engine/exception.hxx>

namespace Engine
{

namespace EngineException
{
class Run : public Exception::BaseException
{
  public:
    explicit Run(const std::string &);
};
} // namespace EngineException
} // namespace Engine