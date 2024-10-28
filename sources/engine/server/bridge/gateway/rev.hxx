#pragma once

#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>
#include <engine/server/focades/rev/disassembly/capstone/capstone.hxx>
#include <engine/interfaces/igateway.hxx>
#include <memory>

#define BASE_REV API_PREFIX "/rev"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            class Rev : public interface::IGateway
            {
              public:
                Rev(Server &);
                ~Rev();

                void load() const override;

              private:
                Server &m_server;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::WebSocket> m_socket_capstone_x64;
                std::unique_ptr<gateway::WebSocket> m_socket_capstone_arm64;

                std::unique_ptr<focades::rev::disassembly::Capstone>
                    m_capstone_x64;
                std::unique_ptr<focades::rev::disassembly::Capstone>
                    m_capstone_arm64;

                void prepare();
                void capstone_x64();
                void capstone_arm64();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine