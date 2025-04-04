#ifdef ENGINE_PRO

#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>
#include <engine/server/gateway/web/web.hxx>

namespace engine::server::gateway::web::extend
{
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

                auto instance = std::make_shared<gateway::Web>();
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
                        if (callback_response.is<crow::response>()) {
                            return static_cast<crow::response &&>(
                                callback_response.as<crow::response>());
                        } else if (callback_response.is<
                                       crow::mustache::rendered_template>()) {
                            return static_cast<crow::response &&>(
                                callback_response
                                    .as<crow::mustache::rendered_template>());
                        }

                        return crow::response(200);
                    },
                    method_list);

                return instance;
            }));
    }
} // namespace engine::server::gateway::web::extend

#endif