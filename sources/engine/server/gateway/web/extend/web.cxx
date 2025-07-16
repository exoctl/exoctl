#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <mutex>

namespace engine::server::gateway::web::extend
{
    void Web::bind_web()
    {
        plugins::Plugins::lua.state.new_usertype<web::Web>(
            "Web",
            "new",
            sol::overload([](Server &server,
                             const std::string &url,
                             const sol::protected_function callback) {
                const std::shared_ptr<gateway::web::Web> instance =
                    std::make_shared<gateway::web::Web>();

                instance->setup(
                    &server,
                    url,
                    [callback](
                        const crow::request &req) -> const crow::response {
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
                    });

                return instance;
            }));
    }

    void Web::_plugins()
    {
        Web::bind_web();
    }
} // namespace engine::server::gateway::web::extend