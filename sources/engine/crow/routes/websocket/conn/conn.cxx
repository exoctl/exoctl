#include <engine/crow/routes/websocket/conn/conn.hxx>

namespace Crow
{
namespace Socket
{
Context::Context(Parser::Toml &p_config)
    : m_conn(0), m_config(p_config),
      m_whitelist(GET_TOML_TBL_VALUE(
          p_config, array, "crow", "websocket_conn_whitelist"))
{
}

Context::~Context() {}

const void Context::conn_erase(crow::websocket::connection *p_conn)
{
    m_conn.erase(p_conn);
}

const void Context::conn_broadcast(crow::websocket::connection *p_conn,
                                   const std::string p_msg) const
{
    if (m_conn.find(p_conn) != m_conn.end())
        p_conn->send_text(p_msg);
}

const void Context::conn_add(crow::websocket::connection *p_conn)
{
    m_conn.insert(p_conn);
}

const std::size_t Context::conn_size() const { return m_conn.size(); }

const std::string
Context::conn_get_remote_ip(crow::websocket::connection *p_conn) const
{
    return (m_conn.find(p_conn) != m_conn.end()) ? p_conn->get_remote_ip()
                                                 : nullptr;
}

const bool Context::conn_check_whitelist(const crow::request *p_request)
{
    for (const auto &list : m_whitelist)
        if (const auto str = list.as_string())
        {
            if (p_request->remote_ip_address == str->get())
                return true;
        }

    return false;
}
} // namespace Socket
} // namespace Crow