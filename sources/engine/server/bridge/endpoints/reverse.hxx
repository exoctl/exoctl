#pragma once

#include  <engine/interfaces/iendpoints.hxx>
#include <engine/server/focades/reverse/disassembly/capstone/capstone.hxx>
#include <engine/server/gateway/map/map.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_REV API_PREFIX "/rev"

namespace engine::server::bridge::endpoints
{

    class Reverse : public interface::IEndpoints
    {
      public:
        Reverse(Server &);
        ~Reverse() = default;

        void load() const override;

      private:
        Server &m_server;
        mutable engine::server::gateway::Map m_map;

        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_x64_little;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_arm64_little;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_x64_big;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_capstone_arm64_big;

        std::unique_ptr<focades::reverse::disassembly::Capstone>
            m_capstone_x64_little;
        std::unique_ptr<focades::reverse::disassembly::Capstone>
            m_capstone_arm64_little;

        std::unique_ptr<focades::reverse::disassembly::Capstone>
            m_capstone_arm64_big;

        void prepare();
        void capstone_x64_little();
        void capstone_arm64_little();
        void capstone_arm64_big();
    };
} // namespace engine::server::bridge::endpoints
