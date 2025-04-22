#include <engine/bridge/endpoints/parser/parser.hxx>
#include <engine/server/gateway/websocket/responses/responses.hxx>

namespace engine::bridge::endpoints
{
    Parser::Parser()
        : m_map(BASE_PARSER),
          m_parser_elf(std::make_unique<focades::parser::binary::elf::ELF>()),
          m_parser_macho(
              std::make_unique<focades::parser::binary::macho::MACHO>()),
          m_parser_pe(std::make_unique<focades::parser::binary::pe::PE>()),
          m_parser_dex(std::make_unique<focades::parser::binary::dex::DEX>()),
          m_parser_art(std::make_unique<focades::parser::binary::art::ART>())
    {
    }

    void Parser::setup(server::Server &p_server)
    {
        m_server = &p_server;

        if (!p_server.config->get("bridge.endpoint.parser.enable")
                 .value<bool>()
                 .value()) {
            m_server->log->warn("Gateway parser not enabled");
        } else {
            // add new routes
            Parser::parser_elf();
            Parser::parser_macho();
            Parser::parser_pe();
            Parser::parser_dex();
            Parser::parser_art();
        }
    }

    void Parser::load() const
    {
        if (m_server->config->get("bridge.endpoint.parser.enable")
                .value<bool>()
                .value()) {
            m_map.get_routes(
                [&](const std::string p_route) { m_map.call_route(p_route); });
        }
    }

    void Parser::parser_pe()
    {
        m_map.add_route("/binary/lief/pe", [&]() {
            m_socket_pe =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_pe->setup(
                *m_server,
                BASE_PARSER "/binary/lief/pe",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        TRY_BEGIN()
                        m_parser_pe->parse_bytes(
                            p_data,
                            [&](focades::parser::binary::pe::record::DTO
                                    *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_parser_pe->dto_json(p_dto).to_string());
                            });
                        TRY_END()
                        CATCH(engine::parser::binary::lief::exception::Parser, {
                            p_context.broadcast_text(
                                &p_conn,
                                server::gateway::websocket::responses::
                                    BadRequests::to_json()
                                        .to_string());
                        })
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

    void Parser::parser_dex()
    {
        m_map.add_route("/binary/lief/dex", [&]() {
            m_socket_dex =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_dex->setup(
                *m_server,
                BASE_PARSER "/binary/lief/dex",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        TRY_BEGIN()
                        m_parser_dex->parse_bytes(
                            p_data,
                            [&](focades::parser::binary::dex::record::DTO
                                    *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_parser_dex->dto_json(p_dto).to_string());
                            });
                        TRY_END()
                        CATCH(engine::parser::binary::lief::exception::Parser, {
                            p_context.broadcast_text(
                                &p_conn,
                                server::gateway::websocket::responses::
                                    BadRequests::to_json()
                                        .to_string());
                        })
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

    void Parser::parser_elf()
    {
        m_map.add_route("/binary/lief/elf", [&]() {
            m_socket_elf =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_elf->setup(
                *m_server,
                BASE_PARSER "/binary/lief/elf",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        TRY_BEGIN()
                        m_parser_elf->parse_bytes(
                            p_data,
                            [&](focades::parser::binary::elf::record::DTO
                                    *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_parser_elf->dto_json(p_dto).to_string());
                            });
                        TRY_END()
                        CATCH(engine::parser::binary::lief::exception::Parser, {
                            p_context.broadcast_text(
                                &p_conn,
                                server::gateway::websocket::responses::
                                    BadRequests::to_json()
                                        .to_string());
                        })
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

    void Parser::parser_art()
    {
        m_map.add_route("/binary/lief/art", [&]() {
            m_socket_art =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_art->setup(
                *m_server,
                BASE_PARSER "/binary/lief/art",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        TRY_BEGIN()
                        m_parser_art->parse_bytes(
                            p_data,
                            [&](focades::parser::binary::art::record::DTO
                                    *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_parser_art->dto_json(p_dto).to_string());
                            });
                        TRY_END()
                        CATCH(engine::parser::binary::lief::exception::Parser, {
                            p_context.broadcast_text(
                                &p_conn,
                                server::gateway::websocket::responses::
                                    BadRequests::to_json()
                                        .to_string());
                        })
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

    void Parser::parser_macho()
    {
        m_map.add_route("/binary/lief/macho", [&]() {
            m_socket_macho =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_macho->setup(
                *m_server,
                BASE_PARSER "/binary/lief/macho",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    if (p_is_binary) {
                        TRY_BEGIN()
                        m_parser_macho->parse_bytes(
                            p_data,
                            [&](focades::parser::binary::macho::record::DTO
                                    *p_dto) {
                                p_context.broadcast_text(
                                    &p_conn,
                                    m_parser_macho->dto_json(p_dto)
                                        .to_string());
                            });
                        TRY_END()
                        CATCH(engine::parser::binary::lief::exception::Parser, {
                            p_context.broadcast_text(
                                &p_conn,
                                server::gateway::websocket::responses::
                                    BadRequests::to_json()
                                        .to_string());
                        })
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
