#include "conn.hxx"

namespace Connection
{
    Context::Context()
    {
    }

    Context::~Context()
    {
    }

    const void Context::remove_conn(crow::websocket::connection &p_conn)
    {
        m_conn.erase(p_conn.get_remote_ip());
    }
    const void Context::send_msg(const std::string p_ip, const std::string p_msg)
    {
        m_conn.at(p_ip).send_text(p_msg);
    }

    const void Context::add_conn(crow::websocket::connection &p_conn)
    {
        m_conn.insert(std::pair<const std::string, crow::websocket::connection &>(p_conn.get_remote_ip(), p_conn));
    }
    const void Context::remove_all_conn()
    {
    }
}