#pragma once

#include <crow.h>
#include <engine/parser/toml.hxx>
#include <list>
#include <unordered_set>

namespace crowapp
{
    namespace bridge
    {
        namespace websocket
        {
            class Context
            {
              public:
                Context(parser::Toml &);
                ~Context();

                /**
                 * @brief used in onaccept to check if ip is whitelisted
                 * @details  if ip listed, return true else false
                 * @return true
                 * @return false
                 */
                const bool context_check_whitelist(const crow::request *);
                const void context_add(crow::websocket::connection *);
                const void context_erase(crow::websocket::connection *);
                const std::size_t context_size() const;
                const void context_broadcast(crow::websocket::connection *,
                                          const std::string) const;

                /**
                 * @brief return what ip connected
                 *
                 * @return const std::string
                 * @return nullptr
                 */
                const std::string context_get_remote_ip(
                    crow::websocket::connection *) const;

              private:
                std::unordered_set<crow::websocket::connection *> m_context;
                parser::Toml &m_config;
                toml::array m_whitelist;
            };
        } // namespace WebSocketManager
    } // namespace BridgeManager
} // namespace crowapp