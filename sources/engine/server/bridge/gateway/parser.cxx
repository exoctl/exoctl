#include <engine/server/bridge/gateway/parser.hxx>
#include <engine/server/bridge/gateway/websocket/responses/responses.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {

            Parser::Parser(Server &p_server)
                : m_server(p_server), m_map(BASE_PARSER)
            {
                Parser::prepare();

                // add new routes
                Parser::parser_elf();
                Parser::parser_macho();
                Parser::parser_pe();
                Parser::parser_dex();
                Parser::parser_art();
            }

            Parser::~Parser()
            {
            }

            void Parser::load() const
            {
                m_map.get_routes([&](const std::string p_route) {
                    m_map.call_route(p_route);
                });
            }

            void Parser::prepare()
            {
                LOG(m_server.get_log(),
                    info,
                    "Preparing gateway parser routes ...");

                m_parser_elf = std::make_unique<focades::parser::binary::ELF>();
                m_parser_macho =
                    std::make_unique<focades::parser::binary::MACHO>();
                m_parser_pe = std::make_unique<focades::parser::binary::PE>();
                m_parser_dex = std::make_unique<focades::parser::binary::DEX>();
            }

            void Parser::parser_pe()
            {
                m_map.add_route("/binary/lief/pe", [&]() {
                    m_socket_pe = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_PARSER "/binary/lief/pe",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_parser_pe->parse_bytes(
                                    p_data,
                                    [&](focades::parser::binary::pe::record::DTO
                                            *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_parser_pe->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                p_context.broadcast_text(
                                    &p_conn,
                                    gateway::websocket::responses::
                                        UnsupportedData::to_json()
                                            .to_string());
                            }
                        });
                });
            }

            void Parser::parser_dex()
            {
                m_map.add_route("/binary/lief/dex", [&]() {
                    m_socket_dex = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_PARSER "/binary/lief/dex",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_parser_dex->parse_bytes(
                                    p_data,
                                    [&](focades::parser::binary::dex::record::
                                            DTO *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_parser_dex->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                p_context.broadcast_text(
                                    &p_conn,
                                    gateway::websocket::responses::
                                        UnsupportedData::to_json()
                                            .to_string());
                            }
                        });
                });
            }

            void Parser::parser_elf()
            {
                m_map.add_route("/binary/lief/elf", [&]() {
                    m_socket_elf = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_PARSER "/binary/lief/elf",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_parser_elf->parse_bytes(
                                    p_data,
                                    [&](focades::parser::binary::elf::record::
                                            DTO *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_parser_elf->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                p_context.broadcast_text(
                                    &p_conn,
                                    gateway::websocket::responses::
                                        UnsupportedData::to_json()
                                            .to_string());
                            }
                        });
                });
            }

            void Parser::parser_art()
            {
                m_map.add_route("/binary/lief/art", [&]() {
                    m_socket_art = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_PARSER "/binary/lief/art",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_parser_art->parse_bytes(
                                    p_data, 
                                    [&](focades::parser::binary::art::record::
                                            DTO *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_parser_art->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                p_context.broadcast_text(
                                    &p_conn,
                                    gateway::websocket::responses::
                                        UnsupportedData::to_json()
                                            .to_string());
                            }
                        });
                });
            }

            void Parser::parser_macho()
            {
                m_map.add_route("/binary/lief/macho", [&]() {
                    m_socket_macho = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_PARSER "/binary/lief/macho",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            if (p_is_binary) {
                                m_parser_macho->parse_bytes(
                                    p_data,
                                    [&](focades::parser::binary::macho::record::
                                            DTO *p_dto) {
                                        p_context.broadcast_text(
                                            &p_conn,
                                            m_parser_macho->dto_json(p_dto)
                                                .to_string());
                                    });
                            } else {
                                p_context.broadcast_text(
                                    &p_conn,
                                    gateway::websocket::responses::
                                        UnsupportedData::to_json()
                                            .to_string());
                            }
                        });
                });
            }

        } // namespace bridge
    } // namespace server
} // namespace engine
