#include <engine/server/gateway/websocket/context/context.hxx>
#include <engine/server/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/server/gateway/websocket/responses/responses.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>

namespace engine::server::gateway::websocket
{
    void WebSocket::setup(Server *p_server,
                          const std::string &p_url,
                          uint64_t p_max_payload,
                          on_message_callback on_message,
                          on_error_callback on_error,
                          on_accept_callback on_accept,
                          on_open_callback on_open,
                          on_close_callback on_close)
    {
        m_server = &*p_server;
        m_url = p_url;
        m_on_message = on_message;
        m_on_error = on_error;
        m_on_accept = on_accept;
        m_on_open = on_open;
        m_on_close = on_close;

        m_server->log->info("Creating WebSocket route for URL: '{}'", m_url);

        m_server->get()
            .route_dynamic(m_url)
            .middlewares<crow::App<middleware::websocket::JWTAuth>,
                         middleware::websocket::JWTAuth>()
            .websocket(&m_server->get())
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
                    m_on_message(m_context, p_conn, p_data, p_is_binary);
            })
            .onerror([&](crow::websocket::connection &p_conn,
                         const std::string &p_error) {
                WebSocket::def_error_connection(&p_conn, p_error);
                if (m_on_error)
                    m_on_error(m_context, p_conn, p_error);
            })
            .onaccept([&](const crow::request &p_req, void **p_userdata) {
                return (!m_on_accept)
                           ? WebSocket::def_accept_connection(&p_req)
                           : m_on_accept(m_context, p_req, p_userdata);
            })
            .validate();
    }

    const std::size_t WebSocket::size_connections() const
    {
        return m_context.size();
    }

    void WebSocket::def_close_connection(crow::websocket::connection *p_conn,
                                         const std::string &p_reason)
    {
        std::lock_guard<std::mutex> _(m_mtx);
        m_context.erase(p_conn);

        m_server->log->warn(
            "Connection {} closed: reason = '{}'", m_url, p_reason);
    }

    void WebSocket::def_open_connection(crow::websocket::connection *p_conn)
    {
        std::lock_guard<std::mutex> _(m_mtx);
        m_context.add(p_conn);
        m_context.broadcast_text(
            p_conn, websocket::responses::Connected::to_json().tostring());

        m_server->log->info(
            "Connection opened {} from IP: '{}',  SubProtocol : "
            "'{}'",
            m_url,
            m_context.get_remote_ip(p_conn),
            m_context.get_subprotocol(p_conn));
    }

    bool WebSocket::def_accept_connection(const crow::request *p_req)
    {
        std::lock_guard<std::mutex> _(m_mtx);
        // auto &session =
        //     m_server->get().get_context<Session>(*p_req);
        // fmt::print("{}", session.get("Cookie", "a"));
        return true;
    }

    void WebSocket::def_message_connection(
        crow::websocket::connection *p_connection, const std::string &p_data)
    {
        std::lock_guard<std::mutex> _(m_mtx);

        m_server->log->debug(
            "Message received on route '{}': data size = {} from "
            "IP: "
            "{}",
            m_url,
            p_data.size(),
            p_connection->get_remote_ip());
    }

    void WebSocket::def_error_connection(
        crow::websocket::connection *p_connection, const std::string &p_error)
    {
        std::lock_guard<std::mutex> _(m_mtx);

        m_server->log->error("Error on route '{}': error = {}", m_url, p_error);
    }

    // void WebSocket::_plugins()
    //{
    //     plugins::Plugins::lua.state.new_usertype<WebSocket>(
    //         "WebSocket",
    //         "new",
    //         sol::factories([](Server &server,
    //                           const std::string &url,
    //                           uint64_t max_payload,
    //                           sol::function on_message,
    //                           sol::function on_error,
    //                           sol::function on_accept,
    //                           sol::function on_open,
    //                           sol::function on_close) {
    //             WebSocket *instance = new WebSocket();
    //             instance->setup(
    //                 server,
    //                 url,
    //                 max_payload,
    //                 // on_message_callback
    //                 [on_message](websocket::Context &ctx,
    //                              crow::websocket::connection &conn,
    //                              const std::string &data,
    //                              bool is_binary) {
    //                     if (on_message.valid())
    //                         on_message(ctx, conn, data, is_binary);
    //                 },
    //                 // on_error_callback
    //                 [on_error](websocket::Context &ctx,
    //                            crow::websocket::connection &conn,
    //                            const std::string &error) {
    //                     if (on_error.valid())
    //                         on_error(ctx, conn, error);
    //                 },
    //                 // on_accept_callback
    //                 [on_accept](websocket::Context &ctx,
    //                             const crow::request &req,
    //                             void **userdata) -> bool {
    //                     if (on_accept.valid())
    //                         return on_accept(ctx, req, userdata);
    //                     return true;
    //                 },
    //                 // on_open_callback
    //                 [on_open](websocket::Context &ctx,
    //                 crow::websocket::connection &conn) {
    //                     if (on_open.valid())
    //                         on_open(ctx, conn);
    //                 },
    //                 // on_close_callback
    //                 [on_close](websocket::Context &ctx,
    //                            crow::websocket::connection &conn,
    //                            const std::string &reason,
    //                            uint16_t code) {
    //                     if (on_close.valid())
    //                         on_close(ctx, conn, reason, code);
    //                 });
    //             return instance;
    //         }));
    // }
} // namespace engine::server::gateway