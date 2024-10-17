#pragma once

#include <engine/crowapp/bridge/gateway/map/map.hxx>
#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>
#include <engine/crowapp/focades/parser/binary/lief/elf/elf.hxx>
#include <engine/crowapp/focades/parser/binary/lief/macho/macho.hxx>
#include <engine/crowapp/focades/parser/binary/lief/pe/pe.hxx>
#include <engine/interfaces/igateway.hxx>

#define BASE_PARSER API_PREFIX "/parser"

namespace engine
{
    namespace crowapp
    {
        namespace bridge
        {
            class Parser : public interface::IGateway
            {
              public:
                Parser(CrowApp &);
                ~Parser();

                void load() const override;

              private:
                CrowApp &m_crowapp;
                mutable gateway::Map m_map;

                std::unique_ptr<focades::parser::binary::ELF> m_parser_elf;
                std::unique_ptr<gateway::WebSocket> m_socket_elf;

                std::unique_ptr<focades::parser::binary::PE> m_parser_pe;
                std::unique_ptr<gateway::WebSocket> m_socket_pe;

                std::unique_ptr<focades::parser::binary::MACHO> m_parser_macho;
                std::unique_ptr<gateway::WebSocket> m_socket_macho;

                void prepare();
                void parser_elf();
                void parser_pe();
                void parser_macho();
            };
        } // namespace bridge
    } // namespace crowapp
} // namespace engine