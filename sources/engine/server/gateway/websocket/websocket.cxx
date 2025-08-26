#include <engine/server/gateway/websocket/context/context.hxx>
#include <engine/server/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/server/gateway/responses/responses.hxx>
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
        server_ = &*p_server;
        url_ = p_url;
        on_message_ = on_message;
        on_error_ = on_error;
        on_accept_ = on_accept;
        on_open_ = on_open;
        on_close_ = on_close;

        server_->log->info("Creating WebSocket route for URL: '{}'", url_);

        (*server_)
            .route_dynamic(url_)
            .middlewares<crow::App<middleware::websocket::JWTAuth>,
                         middleware::websocket::JWTAuth>()
            .websocket(server_)
            .max_payload(p_max_payload)
            .onopen([&](crow::websocket::connection &p_conn) {
                WebSocket::def_open_connection(&p_conn);
                if (on_open_)
                    on_open_(context_, p_conn);
            })
            .onclose([&](crow::websocket::connection &p_conn,
                         const std::string &p_reason,
                         uint16_t p_code) {
                WebSocket::def_close_connection(&p_conn, p_reason);
                if (on_close_)
                    on_close_(context_, p_conn, p_reason, p_code);
            })
            .onmessage([&](crow::websocket::connection &p_conn,
                           const std::string &p_data,
                           bool p_is_binary) {
                WebSocket::def_message_connection(&p_conn, p_data);
                if (on_message_)
                    on_message_(context_, p_conn, p_data, p_is_binary);
            })
            .onerror([&](crow::websocket::connection &p_conn,
                         const std::string &p_error) {
                WebSocket::def_error_connection(&p_conn, p_error);
                if (on_error_)
                    on_error_(context_, p_conn, p_error);
            })
            .onaccept([&](const crow::request &p_req, void **p_userdata) {
                return (!on_accept_)
                           ? WebSocket::def_accept_connection(&p_req)
                           : on_accept_(context_, p_req, p_userdata);
            })
            .validate();
    }

    const std::size_t WebSocket::size_connections() const
    {
        return context_.size();
    }

    void WebSocket::def_close_connection(crow::websocket::connection *p_conn,
                                         const std::string &p_reason)
    {
        std::lock_guard<std::mutex> _(mtx_);
        context_.erase(p_conn);

        server_->log->warn(
            "Connection {} closed: reason = '{}'", url_, p_reason);
    }

    void WebSocket::def_open_connection(crow::websocket::connection *p_conn)
    {
        std::lock_guard<std::mutex> _(mtx_);
        context_.add(p_conn);
        context_.broadcast_text(
            p_conn, responses::Connected().tojson().tostring());

        server_->log->info(
            "Connection opened {} from IP: '{}',  SubProtocol : "
            "'{}'",
            url_,
            context_.get_remote_ip(p_conn),
            context_.get_subprotocol(p_conn));
    }

    bool WebSocket::def_accept_connection(const crow::request *p_req)
    {
        std::lock_guard<std::mutex> _(mtx_);
        // auto &session =
        //     server_->get().get_context<Session>(*p_req);
        // fmt::print("{}", session.get("Cookie", "a"));
        return true;
    }

    void WebSocket::def_message_connection(
        crow::websocket::connection *p_connection, const std::string &p_data)
    {
        std::lock_guard<std::mutex> _(mtx_);

        server_->log->debug(
            "Message received on route '{}': data size = {} from "
            "IP: "
            "{}",
            url_,
            p_data.size(),
            p_connection->get_remote_ip());
    }

    void WebSocket::def_error_connection(
        crow::websocket::connection *p_connection, const std::string &p_error)
    {
        std::lock_guard<std::mutex> _(mtx_);

        server_->log->error("Error on route '{}': error = {}", url_, p_error);
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
} // namespace engine::server::gateway::websocket