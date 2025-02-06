#pragma once

#include <crow.h>
#include <engine/plugins/plugins.hxx>
#include <engine/server/bridge/gateway/web/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>

namespace engine::server::bridge::gateway
{
    template <typename... Args> class Web : public interface::IPlugins
    {
      public:
        using on_request_callback =
            std::function<crow::response(const crow::request &, Args...)>;

        Web(Server &p_server,
            const std::string &p_url,
            on_request_callback on_request)
            : m_server(p_server), m_url(p_url), m_on_request(on_request)
        {
            LOG(m_server.get_log(),
                info,
                "Creating HTTP route for URL: '{}'",
                m_url);

            m_server.get()
                .route_dynamic(m_url)
                .middlewares<crow::App<middleware::web::JWTAuth>,
                             middleware::web::JWTAuth>()(m_on_request);
            m_server.get().validate();

            Web::register_plugins();
        }

        void register_plugins() override
        {
            sol::state &lua = plugins::Plugins::lua.state;
            lua.new_usertype<Web>(
                "Web",
                "new",
                sol::factories([](Server &server,
                                  const std::string &url,
                                  sol::function callback) {
                    return new Web(server,
                                   url,
                                   [callback](const crow::request &req,
                                              Args... args) -> crow::response {
                                       callback(req, args...);
                                       return crow::response(200);
                                   });
                }));
        }

        ~Web() = default;

      private:
        Server &m_server;
        std::string m_url;
        on_request_callback m_on_request;
    };
} // namespace engine::server::bridge::gateway