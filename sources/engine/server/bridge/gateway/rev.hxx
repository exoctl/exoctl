#pragma once

#include <engine/interfaces/igateway.hxx>
#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/websocket/websocket.hxx>
#include <engine/server/focades/rev/disassembly/capstone/capstone.hxx>
#include <engine/server/server.hxx>
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
                ~Rev() = default;

                void load() const override;

              private:
                Server &m_server;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::WebSocket>
                    m_socket_capstone_x64_little;
                std::unique_ptr<gateway::WebSocket>
                    m_socket_capstone_arm64_little;
                std::unique_ptr<gateway::WebSocket>
                    m_socket_capstone_x64_big;
                std::unique_ptr<gateway::WebSocket>
                    m_socket_capstone_arm64_big;

                std::unique_ptr<focades::rev::disassembly::Capstone>
                    m_capstone_x64_little;
                std::unique_ptr<focades::rev::disassembly::Capstone>
                    m_capstone_arm64_little;

                std::unique_ptr<focades::rev::disassembly::Capstone>
                    m_capstone_arm64_big;

                void prepare();
                void capstone_x64_little();
                void capstone_arm64_little();
                void capstone_arm64_big();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine