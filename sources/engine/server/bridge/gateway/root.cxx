#include <engine/plugins/plugins.hxx>
#include <engine/server/bridge/gateway/root.hxx>
#include <engine/server/bridge/gateway/websocket/responses/responses.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            Root::Root(Server &p_server) : m_server(p_server), m_map(BASE_ROOT)
            {
                Root::prepare();

                // add new routes
                Root::root();
                Root::plugins();
            }

            Root::~Root()
            {
            }

            void Root::load() const
            {
                m_map.get_routes([&](const std::string p_route) {
                    m_map.call_route(p_route);
                });
            }

            void Root::prepare()
            {
                LOG(m_server.get_log(),
                    info,
                    "Preparing gateway root routes ...");
            }

            void Root::plugins()
            {
                m_map.add_route("/plugins", [&]() {
                    m_web_root = std::make_unique<
                        engine::server::bridge::gateway::Web<>>(
                        m_server,
                        API_PREFIX BASE_ROOT "plugins",
                        [](const crow::request &req) -> crow::response {
                            crow::json::wvalue x;

                            x["lua"]["state_memory"] = std::format(
                                "{:x}",
                                plugins::Plugins::lua.state.memory_used());

                            std::vector<crow::json::wvalue> scripts_json;
                            for (const auto &script :
                                 plugins::Plugins::lua.scripts) {
                                scripts_json.push_back(
                                    {{"path", script.path},
                                     {"name", script.name},
                                     {"type",
                                      script.type == engine::lua::record::
                                                         script::SCRIPT_FILE
                                          ? "file"
                                          : "buffer"}});
                            }

                            x["lua"]["scripts"] = std::move(scripts_json);

                            return x;
                        });
                });
            }

            void Root::root()
            {
                m_map.add_route(BASE_ROOT, [&]() {
                    m_web_root = std::make_unique<
                        engine::server::bridge::gateway::Web<>>(
                        m_server,
                        BASE_ROOT,
                        [](const crow::request &req) -> crow::response {
                            return crow::response(
                                200, "Skull 1.0.250202 feb 02, 2025");
                        });
                });
            }
        } // namespace bridge
    } // namespace server
} // namespace engine