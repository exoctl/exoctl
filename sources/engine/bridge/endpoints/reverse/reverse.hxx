#pragma once

#include <engine/bridge/focades/reverse/disassembly/capstone/capstone.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_REV API_PREFIX("reverse")

namespace engine::bridge::endpoints
{

    class Reverse : public interface::IEndpoint
    {
      public:
        Reverse();
        ~Reverse() = default;

        void setup(server::Server &);
        void load() const override;

      private:
        server::Server *m_server;
        mutable map::Map m_map;

        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_x64_little;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_arm64_little;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_x64_big;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_arm64_big;

        std::unique_ptr<focades::reverse::disassembly::capstone::Capstone>
            m_capstone_x64_little;
        std::unique_ptr<focades::reverse::disassembly::capstone::Capstone>
            m_capstone_arm64_little;

        std::unique_ptr<focades::reverse::disassembly::capstone::Capstone>
            m_capstone_arm64_big;

        void capstone_x64_little();
        void capstone_arm64_little();
        void capstone_arm64_big();
    };
} // namespace engine::bridge::endpoints
