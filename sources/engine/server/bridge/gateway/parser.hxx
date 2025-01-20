#pragma once

#include <engine/interfaces/igateway.hxx>
#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/websocket/websocket.hxx>
#include <engine/server/focades/parser/binary/lief/art/art.hxx>
#include <engine/server/focades/parser/binary/lief/dex/dex.hxx>
#include <engine/server/focades/parser/binary/lief/elf/elf.hxx>
#include <engine/server/focades/parser/binary/lief/macho/macho.hxx>
#include <engine/server/focades/parser/binary/lief/pe/pe.hxx>

#define BASE_PARSER API_PREFIX "/parser"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            class Parser : public interface::IGateway
            {
              public:
                Parser(Server &);
                ~Parser();

                void load() const override;

              private:
                Server &SERVER_INSTANCE;
                mutable gateway::Map m_map;

                std::unique_ptr<focades::parser::binary::ELF> m_parser_elf;
                std::unique_ptr<gateway::WebSocket> m_socket_elf;

                std::unique_ptr<focades::parser::binary::PE> m_parser_pe;
                std::unique_ptr<gateway::WebSocket> m_socket_pe;

                std::unique_ptr<focades::parser::binary::MACHO> m_parser_macho;
                std::unique_ptr<gateway::WebSocket> m_socket_macho;

                std::unique_ptr<focades::parser::binary::DEX> m_parser_dex;
                std::unique_ptr<gateway::WebSocket> m_socket_dex;

                std::unique_ptr<focades::parser::binary::ART> m_parser_art;
                std::unique_ptr<gateway::WebSocket> m_socket_art;

                void prepare();
                void parser_elf();
                void parser_pe();
                void parser_dex();
                void parser_art();
                void parser_macho();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine