#include <engine/server/bridge/gateway/root.hxx>
#include <engine/server/bridge/gateway/websocket/responses/responses.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            Root::Root(Server &p_server)
                : m_server(p_server), m_map(BASE_ROOT)
            {
                Root::prepare();

                // add new routes
                Root::root();
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

            void Root::root()
            {
                m_map.add_route(BASE_ROOT, [&]() {
                    m_web_root = std::make_unique<
                        engine::server::bridge::gateway::Web<>>(
                        m_server,
                        BASE_ROOT,
                        [](const crow::request &req) -> crow::response {
                            return crow::response(200, "Skull 1.0.250202 feb 02, 2025");
                        });
                });
            }
        } // namespace bridge
    } // namespace server
} // namespace engine