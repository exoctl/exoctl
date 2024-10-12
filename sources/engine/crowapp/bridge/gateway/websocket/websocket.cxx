#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>

namespace crowapp
{
    namespace bridge
    {
        namespace gateway
        {
            WebSocket::WebSocket(CrowApp &p_crow,
                                 const std::string &p_url,
                                 uint64_t p_max_payload,
                                 on_message_callback on_message,
                                 on_error_callback on_error,
                                 on_accept_callback on_accept,
                                 on_open_callback on_open,
                                 on_close_callback on_close)
                : m_crow(p_crow), m_url(p_url), m_context(p_crow.get_config()),
                  m_on_message(on_message), m_on_error(on_error),
                  m_on_accept(on_accept), m_on_open(on_open),
                  m_on_close(on_close)
            {
                LOG(m_crow.get_log(),
                    info,
                    "Creating WebSocket route for URL: '{}'",
                    m_url);

                m_crow.get_app()
                    .route_dynamic(m_url)
                    .websocket(&m_crow.get_app())
                    .max_payload(p_max_payload)
                    .onopen([&](crow::websocket::connection &p_conn) {
                        WebSocket::def_open_connection(&p_conn);
                        if (m_on_open)
                            m_on_open(m_context, p_conn);
                    })
                    .onclose([&](crow::websocket::connection &p_conn,
                                 const std::string &p_reason,
                                 uint16_t p_code) {
                        WebSocket::def_close_connection(&p_conn, p_reason);
                        if (m_on_close)
                            m_on_close(m_context, p_conn, p_reason, p_code);
                    })
                    .onmessage([&](crow::websocket::connection &p_conn,
                                   const std::string &p_data,
                                   bool p_is_binary) {
                        WebSocket::def_message_connection(&p_conn, p_data);
                        if (m_on_message)
                            m_on_message(
                                m_context, p_conn, p_data, p_is_binary);
                    })
                    .onerror([&](crow::websocket::connection &p_conn,
                                 const std::string &p_error) {
                        WebSocket::def_error_connection(&p_conn, p_error);
                        if (m_on_error)
                            m_on_error(m_context, p_conn, p_error);
                    })
                    .onaccept([&](const crow::request &p_req,
                                  void **p_userdata) {
                        bool accept = WebSocket::def_accept_connection(&p_req);

                        if (m_on_accept && accept)
                            m_on_accept(m_context, p_req, p_userdata);

                        return accept;
                    })
                    .validate();
            }

            WebSocket::~WebSocket()
            {
            }

            const std::size_t WebSocket::size_connections() const
            {
                return m_context.size();
            }

            void WebSocket::def_close_connection(
                crow::websocket::connection *p_conn,
                const std::string &p_reason)
            {
                std::lock_guard<std::mutex> _(m_mtx);
                m_context.erase(p_conn);

                LOG(m_crow.get_log(),
                    warn,
                    "Connection {} closed: reason = '{}'",
                    m_url,
                    p_reason);
            }

            void WebSocket::def_open_connection(
                crow::websocket::connection *p_conn)
            {
                std::lock_guard<std::mutex> _(m_mtx);
                m_context.add(p_conn);
                m_context.broadcast(p_conn, "{\"status\": \"ready\"}");

                LOG(m_crow.get_log(),
                    info,
                    "Connection opened {} from IP: {}",
                    m_url,
                    m_context.get_remote_ip(p_conn));
            }

            bool WebSocket::def_accept_connection(const crow::request *p_req)
            {
                std::lock_guard<std::mutex> _(m_mtx);
                if (m_context.check_whitelist(p_req))
                    return true;

                LOG(m_crow.get_log(),
                    critical,
                    "Connection rejected from IP: {}",
                    p_req->remote_ip_address);

                return false;
            }

            void WebSocket::def_message_connection(
                crow::websocket::connection *p_connection,
                const std::string &p_data)
            {
                std::lock_guard<std::mutex> _(m_mtx);

                LOG(m_crow.get_log(),
                    debug,
                    "Message received on route '{}': data size = {} from "
                    "IP: "
                    "{}",
                    m_url,
                    p_data.size(),
                    p_connection->get_remote_ip());
            }

            void WebSocket::def_error_connection(
                crow::websocket::connection *p_connection,
                const std::string &p_error)
            {
                std::lock_guard<std::mutex> _(m_mtx);

                LOG(m_crow.get_log(),
                    error,
                    "Error on route '{}': error = {}",
                    m_url,
                    p_error);
            }
        } // namespace gateway
    } // namespace bridge
} // namespace crowapp