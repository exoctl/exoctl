#pragma once

#include <engine/crowapp/bridge/gateway/map/map.hxx>
#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/focades/rev/disassembly/capstone/capstone.hxx>
#include <engine/interfaces/igateway.hxx>
#include <memory>

#define BASE_REV API_PREFIX "/rev"

namespace engine
{
    namespace crowapp
    {
        namespace bridge
        {
            class Rev : public interface::IGateway
            {
              public:
                Rev(CrowApp &);
                ~Rev();

                void load() const override;

              private:
                CrowApp &m_crowapp;
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
    } // namespace crowapp
} // namespace engine