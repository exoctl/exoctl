#include <engine/server/bridge/gateway/web/web.hxx>
#include <stdio.h>

namespace engine::server::bridge::gateway
{
    void Web::setup(Server &p_server,
                    const std::string &p_url,
                    on_request_callback on_request,
                    std::vector<crow::HTTPMethod> methods)
    {
        m_server = &p_server;
        m_url = p_url;
        m_on_request = on_request;

        LOG(m_server->get_log(),
            info,
            "Creating HTTP route for URL: '{}' with {} methods",
            m_url,
            methods.size());

        auto &route = m_server->get()
                          .route_dynamic(m_url)
                          .middlewares<crow::App<middleware::web::JWTAuth>,
                                       middleware::web::JWTAuth>();

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
                    break;
                case 5:
                default:
                    route.methods(methods[0],
                                  methods[1],
                                  methods[2],
                                  methods[3],
                                  methods[4]);
                    break;
            }
        } else {
            route.methods(crow::HTTPMethod::GET);
        }

        route(m_on_request);
    }

    void Web::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<Web>(
            "Web",
            "new",
            sol::factories([](Server &server,
                              const std::string &url,
                              sol::function callback,
                              sol::variadic_args methods) {
                std::vector<crow::HTTPMethod> method_list;

                for (auto method : methods) {
                    if (method.is<int>()) {
                        method_list.push_back(
                            static_cast<crow::HTTPMethod>(method.as<int>()));
                    }
                }

                Web *instance = new Web();
                instance->setup(
                    server,
                    "/plugins" + url,
                    [callback](const crow::request &req) -> crow::response {
                        crow::response response(200);

                        if (callback.valid()) {
                            sol::object callback_response =
                                callback.call<sol::object>(req);
                            if (callback_response.is<crow::response>()) {
                                return std::move(
                                    callback_response.as<crow::response>());
                            }
                        }
                        return response;
                    },
                    method_list);

                return instance;
            }));
    }
} // namespace engine::server::bridge::gateway