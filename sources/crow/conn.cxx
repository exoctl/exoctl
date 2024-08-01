#include "conn.hxx"

namespace Connection
{
    Context::Context(void) : m_conn(0)
    {
    }

    Context::~Context()
    {
    }

    const void Context::erase_conn(crow::websocket::connection *p_conn)
    {
        m_conn.erase(p_conn);
    }
    const void Context::send_msg(crow::websocket::connection *p_conn, const std::string p_msg)
    {
        p_conn->send_text(p_msg);
    }

    const void Context::add_conn(crow::websocket::connection *p_conn)
    {
        m_conn.insert(p_conn);
    }
    const void Context::remove_all_conn()
    {
    }
}