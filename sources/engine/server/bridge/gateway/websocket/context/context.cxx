#include <engine/server/bridge/gateway/websocket/context/context.hxx>

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
                    Context::Context(configuration::Configuration &p_config)
                        : m_context(0), m_config(p_config)
                    {
                    }

                    Context::~Context()
                    {
                    }

                    const void Context::erase(
                        crow::websocket::connection *p_conn)
                    {
                        m_context.erase(p_conn);
                    }

                    void Context::broadcast_text(
                        crow::websocket::connection *p_conn,
                        const std::string p_msg) const
                    {
                        if (m_context.find(p_conn) != m_context.end())
                            p_conn->send_text(p_msg);
                    }

                    void Context::broadcast_binary(
                        crow::websocket::connection *p_conn,
                        const std::string p_msg) const
                    {
                        if (m_context.find(p_conn) != m_context.end())
                            p_conn->send_binary(p_msg);
                    }

                    const void Context::add(crow::websocket::connection *p_conn)
                    {
                        m_context.insert(p_conn);
                    }

                    const std::size_t Context::size() const
                    {
                        return m_context.size();
                    }

                    const std::string Context::get_remote_ip(
                        crow::websocket::connection *p_conn) const
                    {
                        return (m_context.find(p_conn) != m_context.end())
                                   ? p_conn->get_remote_ip()
                                   : "";
                    }

                    const std::string Context::get_subprotocol(
                        crow::websocket::connection *p_conn) const
                    {
                        return (m_context.find(p_conn) != m_context.end())
                                   ? p_conn->get_subprotocol()
                                   : "";
                    }

                    const void Context::close(
                        crow::websocket::connection *p_conn,
                        uint16_t p_code,
                        const std::string &p_message)
                    {
                        if (m_context.find(p_conn) != m_context.end()) {
                            p_conn->close(p_message, p_code);
                            Context::erase(p_conn);
                        }
                    }
                } // namespace websocket
            } // namespace gateway
        } // namespace bridge
    } // namespace server
} // namespace engine