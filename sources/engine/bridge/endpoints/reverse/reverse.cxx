#include <engine/bridge/endpoints/reverse/reverse.hxx>
#include <engine/server/gateway/websocket/responses/responses.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>

namespace engine::bridge::endpoints
{
    Reverse::Reverse()
        : m_map(BASE_REV),
          m_capstone_x64_little(
              std::make_unique<
                  focades::reverse::disassembly::capstone::Capstone>()),
          m_capstone_arm64_little(
              std::make_unique<
                  focades::reverse::disassembly::capstone::Capstone>()),
          m_capstone_arm64_big(
              std::make_unique<
                  focades::reverse::disassembly::capstone::Capstone>())
    {
    }

    void Reverse::setup(server::Server &p_server)
    {
        m_server = &p_server;

        if (!p_server.config->get("bridge.endpoint.reverse.enable")
                 .value<bool>()
                 .value()) {
            m_server->log->warn("Gateway reverse not enabled");
        } else {
            m_capstone_x64_little->setup(
                CS_ARCH_X86,
                static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN));

            m_capstone_arm64_little->setup(CS_ARCH_ARM64,
                                           CS_MODE_LITTLE_ENDIAN);

            m_capstone_arm64_big->setup(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN);

            Reverse::capstone_x64_little();
            Reverse::capstone_arm64_little();
            Reverse::capstone_arm64_big();
        }
    }

    void Reverse::load() const
    {
        if (m_server->config->get("bridge.endpoint.reverse.enable")
                .value<bool>()
                .value()) {
            m_map.get_routes(
                [&](const std::string p_route) { m_map.call_route(p_route); });
        }
    }

    void Reverse::capstone_x64_little()
    {
        m_map.add_route("/disassembly/capstone/x64/endian/little", [&]() {
            m_socket_capstone_x64_little =
                std::make_unique<server::gateway::WebSocket>();
            m_socket_capstone_x64_little->setup(
                *m_server,
                BASE_REV "/disassembly/capstone/x64/endian/little",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        m_capstone_x64_little->disassembly(
                            p_data,
                            [&](focades::reverse::disassembly::capstone::
                                    record::DTO *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_capstone_x64_little->dto_json(p_dto)
                                        .to_string());
                            });
                    } else {
                        p_context.broadcast_text(
                            &p_conn,
                            server::gateway::websocket::responses::
                                UnsupportedData::to_json()
                                    .to_string());
                    }
                });
        });
    }

    void Reverse::capstone_arm64_little()
    {
        m_map.add_route("/disassembly/capstone/arm64/endian/little", [&]() {
            m_socket_capstone_arm64_little =
                std::make_unique<server::gateway::WebSocket>();
            m_socket_capstone_arm64_little->setup(
                *m_server,
                BASE_REV "/disassembly/capstone/arm64/endian/little",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        m_capstone_arm64_little->disassembly(
                            p_data,
                            [&](focades::reverse::disassembly::capstone::
                                    record::DTO *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_capstone_arm64_little->dto_json(p_dto)
                                        .to_string());
                            });
                    } else {
                        p_context.broadcast_text(
                            &p_conn,
                            server::gateway::websocket::responses::
                                UnsupportedData::to_json()
                                    .to_string());
                    }
                });
        });
    }

    void Reverse::capstone_arm64_big()
    {
        m_map.add_route("/disassembly/capstone/arm64/endian/big", [&]() {
            m_socket_capstone_arm64_big =
                std::make_unique<server::gateway::WebSocket>();
            m_socket_capstone_arm64_big->setup(
                *m_server,
                BASE_REV "/disassembly/capstone/arm64/endian/big",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        m_capstone_arm64_big->disassembly(
                            p_data,
                            [&](focades::reverse::disassembly::capstone::
                                    record::DTO *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_capstone_arm64_big->dto_json(p_dto)
                                        .to_string());
                            });
                    } else {
                        p_context.broadcast_text(
                            &p_conn,
                            server::gateway::websocket::responses::
                                UnsupportedData::to_json()
                                    .to_string());
                    }
                });
        });
    }
} // namespace engine::bridge::endpoints