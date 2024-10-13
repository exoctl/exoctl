#pragma once

#include <engine/crowapp/bridge/gateway/map/map.hxx>
#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>
#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
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

                void prepare();
                void parser_elf();
            };
        } // namespace bridge
    } // namespace crowapp
} // namespace engine