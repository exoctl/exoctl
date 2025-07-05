#pragma once

#include <crow.h>
#include <engine/configuration/configuration.hxx>
#include <list>
#include <unordered_set>

namespace engine::server::gateway::websocket
{
    class Context
    {
      public:
        Context();
        ~Context() = default;

        const void add(crow::websocket::connection *);
        const void erase(crow::websocket::connection *);
        const void close(crow::websocket::connection *,
                         uint16_t,
                         const std::string &);
        const std::size_t size() const;
        void broadcast_text(crow::websocket::connection *,
                            const std::string) const;

        void broadcast_binary(crow::websocket::connection *,
                              const std::string) const;

        const std::string get_remote_ip(crow::websocket::connection *) const;

        const std::string get_subprotocol(crow::websocket::connection *) const;

      private:
        std::unordered_set<crow::websocket::connection *> m_context;
    };
} // namespace engine::server::gateway::websocket::Websocket
