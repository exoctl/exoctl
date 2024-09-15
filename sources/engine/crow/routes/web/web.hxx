#pragma once

#include <crow.h>
#include <engine/crow/crow.hxx>
#include <functional>
#include <string>

namespace Crow
{
class Web
{
  public:
    using on_callback = std::function<void()>;

    Web(CrowApp &, const std::string &, on_callback);
    ~Web();
};
} // namespace Crow