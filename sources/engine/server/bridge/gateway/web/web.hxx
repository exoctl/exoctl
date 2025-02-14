#pragma once

#include <crow.h>
#include <engine/plugins/plugins.hxx>
#include <engine/server/bridge/gateway/web/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>
#include <vector>

namespace engine::server::bridge::gateway
{
    class Web : public interface::ISubPlugins<Web>
    {
      public:
        using on_request_callback =
            std::function<crow::response(const crow::request &)>;

        Web() = default;
        ~Web() = default;

        void setup(Server &,
                   const std::string &,
                   on_request_callback,
                   std::vector<crow::HTTPMethod> = {crow::HTTPMethod::GET});
        void _plugins() override;

      private:
        Server *m_server = nullptr;
        std::string m_url;
        on_request_callback m_on_request;
    };
} // namespace engine::server::bridge::gateway
