#pragma once

#include <engine/bridge/focades/parser/binary/lief/art/art.hxx>
#include <engine/bridge/focades/parser/binary/lief/dex/dex.hxx>
#include <engine/bridge/focades/parser/binary/lief/elf/elf.hxx>
#include <engine/bridge/focades/parser/binary/lief/macho/macho.hxx>
#include <engine/bridge/focades/parser/binary/lief/pe/pe.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>

#define BASE_PARSER API_PREFIX("parser")

namespace engine::bridge::endpoints
{

    class Parser : public interface::IEndpoint
    {
      public:
        Parser();
        ~Parser() = default;

        void setup(server::Server &);
        void load() const override;

      private:
        server::Server *m_server;
        mutable map::Map m_map;

        std::unique_ptr<focades::parser::binary::elf::ELF> m_parser_elf;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_elf;
        
        std::unique_ptr<focades::parser::binary::macho::MACHO> m_parser_macho;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_macho;
        
        std::unique_ptr<focades::parser::binary::pe::PE> m_parser_pe;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_pe;

        std::unique_ptr<focades::parser::binary::dex::DEX> m_parser_dex;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_dex;

        std::unique_ptr<focades::parser::binary::art::ART> m_parser_art;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_art;

        void parser_elf();
        void parser_pe();
        void parser_dex();
        void parser_art();
        void parser_macho();
    };
} // namespace engine::bridge::endpoints
