#include <engine/bridge/endpoints/plugins/plugins.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/responses/responses.hxx>

namespace engine::bridge::endpoints
{
    Plugins::Plugins(server::Server &p_server)
        : m_server(p_server), m_map(BASE_PLUGINS)
    {
        Plugins::prepare();

        // Add new routes
        Plugins::plugins();
    }

    void Plugins::load() const
    {
        m_map.get_routes(
            [&](const std::string p_route) { m_map.call_route(p_route); });
    }

    void Plugins::prepare()
    {
        m_server.log->info("Preparing gateway plugins routes ...");
    }

    void Plugins::plugins()
    {
        m_map.add_route(BASE_PLUGINS, [&]() {
            m_web_plugins =
                std::make_unique<engine::server::gateway::web::Web>();
            m_web_plugins->setup(
                &m_server,
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

                    if (!m_server.config->get("plugins.enable")
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