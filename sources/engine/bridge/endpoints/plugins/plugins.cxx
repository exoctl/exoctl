#include <engine/bridge/endpoints/plugins/plugins.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/responses/responses.hxx>

namespace engine::bridge::endpoints
{
    Plugins::Plugins(server::Server &p_server)
        : server_(p_server), map_(BASE_PLUGINS)
    {
        Plugins::prepare();

        // Add new routes
        Plugins::plugins();
    }

    void Plugins::load() const
    {
        map_.get_routes(
            [&](const std::string p_route) { map_.call_route(p_route); });
    }

    void Plugins::prepare()
    {
        server_.log->info("Preparing gateway plugins routes ...");
    }

    void Plugins::plugins()
    {
        map_.add_route(BASE_PLUGINS, [&]() {
            web_plugins_ =
                std::make_unique<engine::server::gateway::web::Web>();
            web_plugins_->setup(
                &server_,
                BASE_PLUGINS,
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::GET) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    if (!server_.config->get("plugins.enable")
                             .value<bool>()
                             .value()) {
                        auto service_unavailable =
                            server::gateway::responses::ServiceUnavailable();
                        return crow::response{
                            service_unavailable.code(),
                            "application/json",
                            service_unavailable.tojson().tostring()};
                    }

                    parser::json::Json json;
                    parser::json::Json lua;
                    lua.add("state_memory",
                            plugins::Plugins::lua.state.memory_used());

                    parser::json::Json scripts_json;
                    for (const auto &script : plugins::Plugins::lua.scripts) {
                        parser::json::Json script_record;
                        script_record.add("path", script.path);
                        script_record.add("name", script.name);
                        script_record.add(
                            "type",
                            script.type ==
                                    engine::lua::record::script::SCRIPT_FILE
                                ? "file"
                                : "buffer");
                        scripts_json.add(script_record);
                    }

                    lua.add("scripts", scripts_json);
                    json.add("lua", lua);

                    auto connected =
                        server::gateway::responses::Connected().add_field(
                            "plugins", json);
                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }
} // namespace engine::bridge::endpoints