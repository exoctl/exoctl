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
        }

        void register_plugins() override
        {
            /* nothing */
        }

        static inline void plugins()
        {
            plugins::Plugins::lua.state.new_usertype<Web>(
                "Web",
                "new",
                sol::factories([](Server &server,
                                  const std::string &url,
                                  sol::function callback) {
                    return new Web(
                        server,
                        std::string("/plugins") + url,
                        [callback](const crow::request &req,
                                   Args... args) -> crow::response {
                            crow::response response(200);

                            if (callback.valid()) {
                                sol::object callback_response =
                                    callback.call<sol::object>(req, args...);

                                if (callback_response.is<crow::response>()) {
                                    return std::move(
                                        callback_response.as<crow::response>());
                                }
                            }

                            return response;
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