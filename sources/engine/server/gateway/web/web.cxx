#include <engine/server/gateway/web/web.hxx>

namespace engine::server::gateway
{
    void Web::setup(Server &p_server,
                    const std::string &p_url,
                    on_request_callback on_request,
                    const std::vector<crow::HTTPMethod> &methods)
    {
        m_server = &p_server;
        m_url = p_url;
        m_on_request = std::move(on_request);

        m_server->log->info("Creating HTTP route for URL: '{}' with {} methods",
                            m_url,
                            methods.size());

        auto &route = m_server->get().route_dynamic(m_url);

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
        route.validate();
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
                method_list.reserve(methods.size());

                for (auto method : methods) {
                    if (method.is<int>()) {
                        method_list.push_back(
                            static_cast<crow::HTTPMethod>(method.as<int>()));
                    }
                }

                auto instance = std::make_shared<Web>();
                instance->setup(
                    server,
                    url,
                    [callback](const crow::request &req) -> crow::response {
                        if (!callback.valid()) {
                            return crow::response(500, "Invalid callback");
                        }

                        sol::protected_function_result result = callback(req);
                        if (!result.valid()) {
                            sol::error err = result;
                            return crow::response(500, err.what());
                        }

                        sol::object callback_response = result;
                        return callback_response.is<crow::response>()
                                   ? std::move(
                                         callback_response.as<crow::response>())
                                   : crow::response(200);
                    },
                    method_list);

                return instance;
            }));
    }
} // namespace engine::server::gateway
