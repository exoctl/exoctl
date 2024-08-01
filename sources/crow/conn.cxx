#include "conn.hxx"

namespace Connection
{
    Context::Context(void) : m_conn(0)
    {
    }

    Context::~Context()
    {
    }

    const void Context::erase_conn(crow::websocket::connection *p_conn,
                                   const std::string &p_reason /*reason for log*/)
    {
        m_conn.erase(p_conn);
        CROW_LOG_INFO << "Connection websocket closed '" << p_reason << "'";
    }
    
    const void Context::send_msg_conn(crow::websocket::connection *p_conn, const std::string p_msg) const
    {
        if (m_conn.find(p_conn) != nullptr)
            p_conn->send_text(p_msg);
    }

    const void Context::add_conn(crow::websocket::connection *p_conn)
    {
        m_conn.insert(p_conn);
        CROW_LOG_INFO << "New websocket connection '" << p_conn->get_remote_ip() << "'";
    }

    const std::size_t Context::size_conn() const
    {
        return m_conn.size();
    }

}