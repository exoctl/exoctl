#pragma once

#include <crow.h>
#include <engine/configuration/configuration.hxx>
#include <list>
#include <unordered_set>

namespace engine
{
    namespace server
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
    } // namespace server
} // namespace engine