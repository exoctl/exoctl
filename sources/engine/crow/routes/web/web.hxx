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
    using on_request_callback =
        std::function<crow::response(const crow::request &)>;

    Web(CrowApp &, const std::string &, on_request_callback);
    ~Web();

  private:
    CrowApp &m_crow;
    std::string m_url;
    on_request_callback m_on_request;
};
} // namespace Crow