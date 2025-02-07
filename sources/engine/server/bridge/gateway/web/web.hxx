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
    template <typename... Args>
    class Web
#ifdef ENGINE_PRO
        : public interface::IPlugins
#endif
    {
      public:
        using on_request_callback =
            std::function<crow::response(const crow::request &, Args...)>;

        Web(Server &p_server,
            const std::string &p_url,
            on_request_callback on_request,
            std::vector<crow::HTTPMethod> methods = {crow::HTTPMethod::GET})
            : m_server(p_server), m_url(p_url), m_on_request(on_request)
        {
            LOG(m_server.get_log(),
                info,
                "Creating HTTP route for URL: '{}' with {} methods",
                m_url,
                methods.size());

            auto &route = m_server.get()
                              .route_dynamic(m_url)
                              .middlewares<crow::App<middleware::web::JWTAuth>,
                                           middleware::web::JWTAuth>();

            /* TODO: This way was what I found to be able to add at least 5
             * methods per endpoint, because Crow doesn't have a nice methods
             * function for bitwise to add several methods using a vector for
             * example */
            if (!methods.empty()) {
                switch (methods.size()) {
                    case 1:
                        route.methods(methods[0]);
                        break;
                    case 2:
                        route.methods(methods[0], methods[1]);
                        break;
                    case 3:
                        route.methods(methods[0], methods[1], methods[2]);
                        break;
                    case 4:
                        route.methods(
                            methods[0], methods[1], methods[2], methods[3]);
                    case 5:
                    default:
                        route.methods(methods[0],
                                      methods[1],
                                      methods[2],
                                      methods[3],
                                      methods[4]);
                }
            } else
                route.methods(crow::HTTPMethod::GET);

            route(m_on_request);
            m_server.get().validate();
        }

#ifdef ENGINE_PRO
        void register_plugins() override
        {
        }
#endif
        static inline void plugins()
        {
            plugins::Plugins::lua.state.new_usertype<Web<>>(
                "Web",
                "new",
                sol::factories([](Server &server,
                                  const std::string &url,
                                  sol::function callback,
                                  sol::variadic_args methods) {
                    std::vector<crow::HTTPMethod> method_list;

                    for (auto method : methods) {
                        if (method.is<int>()) {
                            method_list.push_back(static_cast<crow::HTTPMethod>(
                                method.as<int>()));
                        }
                    }

                    return new Web<>(
                        server,
                        "/plugins" + url,
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
                        },
                        method_list);
                }));
        }

        ~Web() = default;

      private:
        Server &m_server;
        std::string m_url;
        on_request_callback m_on_request;
    };
} // namespace engine::server::bridge::gateway