#include "conn.hxx"

namespace Connection
{
    Context::Context(void) : m_conn(0)
    {
    }

    Context::~Context()
    {
    }

    const void Context::conn_erase(crow::websocket::connection *p_conn,
                                   const std::string &p_reason /*reason for connection is closed*/)
    {
        m_conn.erase(p_conn);
        CROW_LOG_INFO << "Connection websocket closed '" << p_reason << "'";
    }

    const void Context::conn_send_msg(crow::websocket::connection *p_conn, const std::string p_msg) const
    {
        if (m_conn.find(p_conn) != m_conn.end())
            p_conn->send_text(p_msg);
    }

    const void Context::conn_add(crow::websocket::connection *p_conn)
    {
        m_conn.insert(p_conn);
        CROW_LOG_INFO << "New websocket connection '" << p_conn->get_remote_ip() << "'";
    }

    const std::size_t Context::conn_size() const
    {
        return m_conn.size();
    }

    const std::string Context::conn_get_remote_ip(crow::websocket::connection *p_conn)
    {
        return (m_conn.find(p_conn) != m_conn.end()) ? p_conn->get_remote_ip() : nullptr;
    }

}