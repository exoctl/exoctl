#pragma once

#include <crow.h>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>
#include <engine/server/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>
#include <vector>

namespace engine::server::gateway
{
    class Web; // Forward declaration Web plugin

    class Web
    {
      public:
        using on_request_callback =
            std::function<crow::response(const crow::request &)>;
#ifdef ENGINE_PRO
        friend class web::extend::Web;
#endif
        Web() = default;
        ~Web() = default;

        void setup(Server &,
                   const std::string &,
                   on_request_callback,
                   const std::vector<crow::HTTPMethod> & = {
                       crow::HTTPMethod::GET});

      private:
        Server *m_server;
        std::string m_url;
        on_request_callback m_on_request;
    };
} // namespace engine::server::gateway
