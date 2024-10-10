#include <engine/crowapp/bridge/gateway/parser.hxx>

namespace crowapp
{
    namespace bridge
    {

        Parser::Parser(CrowApp &p_crowapp)
            : m_crowapp(p_crowapp), m_map(BASE_PARSER)
        {
            Parser::prepare();

            // add new routes
            Parser::parser_elf();
        }

        Parser::~Parser()
        {
        }

        void Parser::load() const
        {
            m_map.get_routes(
                [&](const std::string p_route) { m_map.call_route(p_route); });
        }

        void Parser::prepare()
        {
            m_parser_elf = std::make_unique<focades::parser::binary::ELF>();
        }

        void Parser::parser_elf()
        {
            m_map.add_route("/binary/elf", [&]() {
                m_socket_elf = std::make_unique<gateway::WebSocket>(
                    m_crowapp,
                    BASE_PARSER "/binary/elf",
                    UINT64_MAX,
                    [&](gateway::websocket::Context &p_context,
                        crow::websocket::connection &p_conn,
                        const std::string &p_data,
                        bool p_is_binary) {
                        m_parser_elf->parser_bytes(
                            "/usr/bin/ls",
                            [&](focades::parser::binary::elf::record::DTO
                                    *p_dto) {
                                p_context.broadcast(
                                    &p_conn,
                                    m_parser_elf->dto_json(p_dto).to_string());
                            });
                    });
            });
        }

    } // namespace bridge
} // namespace crowapp