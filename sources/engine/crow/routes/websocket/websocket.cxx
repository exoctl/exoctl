#include <engine/crow/routes/websocket/websocket.hxx>

namespace Crow
{
WebSocket::WebSocket(CrowApp &p_crow,
                     const std::string &p_url,
                     uint64_t p_max_payload,
                     on_message_callback on_message,
                     on_error_callback on_error,
                     on_accept_callback on_accept,
                     on_open_callback on_open,
                     on_close_callback on_close)
    : m_crow(p_crow), m_url(p_url), m_context(p_crow.crow_get_config()),
      m_on_message(on_message), m_on_error(on_error), m_on_accept(on_accept),
      m_on_open(on_open), m_on_close(on_close)
{
    LOG(m_crow.crow_get_log(),
        info,
        "Creating WebSocket route for URL: '{}'",
        m_url);

    m_crow.crow_get_app()
        .route_dynamic(m_url)
        .websocket(&m_crow.crow_get_app())
        .max_payload(p_max_payload)
        .onopen(
            [this](crow::websocket::connection &p_conn)
            {
                WebSocket::websocket_def_open_connection(&p_conn);
                if (m_on_open)
                    m_on_open(m_context, p_conn);
            })
        .onclose(
            [this](crow::websocket::connection &p_conn,
                   const std::string &p_reason,
                   uint16_t p_code)
            {
                WebSocket::websocket_def_close_connection(&p_conn, p_reason);
                if (m_on_close)
                    m_on_close(m_context, p_conn, p_reason, p_code);
            })
        .onmessage(
            [this](crow::websocket::connection &conn,
                   const std::string &data,
                   bool is_binary)
            {
                if (m_on_message)
                    m_on_message(m_context, conn, data, is_binary);
            })
        .onerror(
            [this](crow::websocket::connection &conn, const std::string &error)
            {
                if (m_on_error)
                    m_on_error(m_context, conn, error);
            })
        .onaccept(
            [this](const crow::request &p_req, void **p_userdata)
            {
                const bool accept =
                    WebSocket::websocket_def_onaccept_connection(&p_req);

                if (m_on_accept && accept)
                    m_on_accept(m_context, p_req, p_userdata);

                return accept;
            });
}

WebSocket::~WebSocket() {}

const std::size_t WebSocket::websocket_size_connections() const
{
    return m_context.conn_size();
}

void WebSocket::websocket_def_close_connection(
    crow::websocket::connection *p_conn, const std::string &p_reason)
{
    std::lock_guard<std::mutex> _(m_mtx);
    m_context.conn_erase(p_conn);
    LOG(m_crow.crow_get_log(),
        info,
        "Connection closed: reason = '{}'",
        p_reason);
}

void WebSocket::websocket_def_open_connection(
    crow::websocket::connection *p_conn)
{
    std::lock_guard<std::mutex> _(m_mtx);
    m_context.conn_add(p_conn);
    m_context.conn_broadcast(p_conn, "{\"status\": \"ready\"}");

    LOG(m_crow.crow_get_log(),
        info,
        "Connection opened from IP: {}",
        m_context.conn_get_remote_ip(p_conn));
}

bool WebSocket::websocket_def_onaccept_connection(const crow::request *p_req)
{
    std::lock_guard<std::mutex> _(m_mtx);
    if (m_context.conn_check_whitelist(p_req))
        return true;

    LOG(m_crow.crow_get_log(),
        warn,
        "Connection rejected from IP: {}",
        p_req->remote_ip_address);

    return false;
}

} // namespace Crow
