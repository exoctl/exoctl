#include <engine/server/gateway/websocket/context/context.hxx>

namespace engine::server::gateway::websocket
{
    Context::Context() : m_context(0)
    {
    }

    const void Context::erase(crow::websocket::connection *p_conn)
    {
        m_context.erase(p_conn);
    }

    void Context::broadcast_text(crow::websocket::connection *p_conn,
                                 const std::string p_msg) const
    {
        if (m_context.find(p_conn) != m_context.end())
            p_conn->send_text(p_msg);
    }

    void Context::broadcast_binary(crow::websocket::connection *p_conn,
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

    const void Context::close(crow::websocket::connection *p_conn,
                              uint16_t p_code,
                              const std::string &p_message)
    {
        if (m_context.find(p_conn) != m_context.end()) {
            p_conn->close(p_message, p_code);
            Context::erase(p_conn);
        }
    }
} // namespace engine::server::gateway::websocket::Websocket
