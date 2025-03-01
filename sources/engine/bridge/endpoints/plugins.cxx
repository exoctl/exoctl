#ifdef ENGINE_PRO

#include <engine/bridge/endpoints/plugins.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/gateway/websocket/responses/responses.hxx>

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
            m_web_plugins = std::make_unique<engine::server::gateway::Web>();
            m_web_plugins->setup(
                m_server,
                BASE_PLUGINS,
                [&](const crow::request &req) -> crow::response {
                    if (m_server.config->get("plugins.enable")
                            .value<bool>()
                            .value()) {
                        crow::json::wvalue x;

                        x["lua"]["state_memory"] = std::format(
                            "0x{:x}",
                            plugins::Plugins::lua.state.memory_used());

                        std::vector<crow::json::wvalue> scripts_json;
                        for (const auto &script :
                             plugins::Plugins::lua.scripts) {
                            scripts_json.push_back(
                                {{"path", script.path},
                                 {"name", script.name},
                                 {"type",
                                  script.type == engine::lua::record::script::
                                                     SCRIPT_FILE
                                      ? "file"
                                      : "buffer"}});
                        }

                        x["lua"]["scripts"] = std::move(scripts_json);
                        return x;
                    }

                    return crow::response(crow::status::SERVICE_UNAVAILABLE);
                });
        });
    }
} // namespace engine::bridge::endpoints

#endif