#ifdef ENGINE_PRO

#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <mutex>

namespace engine::server::gateway::web::extend
{
    static std::mutex web_mutex;

    void Web::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<Web>(
            "Web",
            "new",
            sol::overload([](Server &server,
                              const std::string &url,
                              const sol::protected_function callback,
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
                        std::lock_guard<std::mutex> lock(web_mutex);

                        if (!callback.valid()) {
                            return crow::response(500, "Invalid callback");
                        }

                        sol::protected_function_result result = callback(req);

                        if (!result.valid()) {
                            return crow::response(500,
                                                  sol::error(result).what());
                        }

                        const sol::object callback_response = result;
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