#pragma once

#include <crow.h>
#include <engine/configuration/configuration.hxx>
#include <list>
#include <unordered_set>

namespace crowapp
{
    namespace bridge
    {
        namespace gateway
        {
            namespace websocket
            {
                    class Context
                    {
                      public:
                        Context(configuration::Configuration &);
                        ~Context();

                        /**
                         * @brief used in onaccept to check if ip is whitelisted
                         * @details  if ip listed, return true else false
                         * @return true
                         * @return false
                         */
                        const bool check_whitelist(const crow::request *);
                        const void add(crow::websocket::connection *);
                        const void erase(crow::websocket::connection *);
                        const std::size_t size() const;
                        const void broadcast(crow::websocket::connection *,
                                             const std::string) const;

                        /**
                         * @brief return what ip connected
                         *
                         * @return const std::string
                         * @return nullptr
                         */
                        const std::string get_remote_ip(
                            crow::websocket::connection *) const;

                      private:
                        std::unordered_set<crow::websocket::connection *>
                            m_context;
                        configuration::Configuration &m_config;
                    };
            } // namespace websocket
        } // namespace gateway
    } // namespace bridge
} // namespace crowapp