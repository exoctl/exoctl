#include <engine/server/bridge/gateway/rev.hxx>
#include <engine/server/bridge/gateway/websocket/responses/responses.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            Rev::Rev(Server &p_server) : m_server(p_server), m_map(BASE_REV)
            {
                Rev::prepare();

                // add new routes
                Rev::capstone_x64();
                Rev::capstone_arm64();
            }

            Rev::~Rev()
            {
            }

            void Rev::load() const
            {
                m_map.get_routes([&](const std::string p_route) {
                    m_map.call_route(p_route);
                });
            }

            void Rev::prepare()
            {
                LOG(m_server.get_log(),
                    info,
                    "Preparing gateway rev routes ...");

                m_capstone_arm64 =
                    std::make_unique<focades::rev::disassembly::Capstone>(
                        CS_ARCH_ARM64, CS_MODE_ARM);
                m_capstone_x64 =
                    std::make_unique<focades::rev::disassembly::Capstone>(
                        CS_ARCH_X86, CS_MODE_64);
            }

            void Rev::capstone_x64()
            {
                m_map.add_route("/disassembly/capstone/x64", [&]() {
                    m_socket_capstone_x64 =
                        std::make_unique<gateway::WebSocket>(
                            m_server,
                            BASE_REV "/disassembly/capstone/x64",
                            UINT64_MAX,
                            [&](gateway::websocket::Context &p_context,
                                crow::websocket::connection &p_conn,
                                const std::string &p_data,
                                bool p_is_binary) {
                                if (p_is_binary) {
                                    m_capstone_x64->disassembly(
                                        p_data,
                                        [&](focades::rev::disassembly::
                                                capstone::record::DTO *p_dto) {
                                            p_context.broadcast_text(
                                                &p_conn,
                                                m_capstone_x64->dto_json(p_dto)
                                                    .to_string());
                                        });
                                } else {
                                    p_context.broadcast_text(
                                        &p_conn,
                                        gateway::websocket::responses::
                                            UnsupportedData::to_json().
                                                to_string());
                                }
                            });
                });
            }

            void Rev::capstone_arm64()
            {
                m_map.add_route("/disassembly/capstone/arm64", [&]() {
                    m_socket_capstone_arm64 = std::make_unique<
                        gateway::WebSocket>(
                        m_server,
                        BASE_REV "/disassembly/capstone/arm64",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_capstone_arm64->disassembly(
                                    p_data,
                                    [&](focades::rev::disassembly::capstone::
                                            record::DTO *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_capstone_arm64->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                 p_context.broadcast_text(
                                        &p_conn,
                                        gateway::websocket::responses::
                                            UnsupportedData::to_json().
                                                to_string());
                                }
                            });
                });
            }

        } // namespace bridge
    } // namespace server
} // namespace engine