#pragma once

#include <crow.h>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>
#include <vector>

namespace engine::server::gateway
{
    class Web
#ifdef ENGINE_PRO
        : public interface::ISubPlugins<Web>
#endif
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

#ifdef ENGINE_PRO
        void _plugins() override;
#endif
      private:
        Server *m_server;
        std::string m_url;
        on_request_callback m_on_request;
    };
} // namespace engine::server::bridge::gateway
