#pragma once

#include <crow.h>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>
#include <engine/server/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>
#include <vector>

namespace engine::server::gateway::web
{
    class Web
    {
      public:
        using on_request_callback =
            std::function<crow::response(const crow::request &)>;
        friend class extend::Web;

        Web() = default;
        ~Web() = default;

        void setup(Server *, const std::string &, on_request_callback);

      private:
        Server *m_server;
        crow::DynamicRule *m_route;
        void active_all_methods();
    };
} // namespace engine::server::gateway::web
