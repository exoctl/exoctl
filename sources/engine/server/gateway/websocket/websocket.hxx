#pragma once

#include <crow.h>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/websocket/context/context.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <mutex>
#include <string>

namespace engine::server::gateway::websocket
{
    class WebSocket
    {
      public:
        using on_error_callback =
            std::function<void(websocket::Context &,
                               crow::websocket::connection &,
                               const std::string &)>;
        using on_accept_callback = std::function<bool(
            websocket::Context &, const crow::request &, void **)>;
        using on_open_callback = std::function<void(
            websocket::Context &, crow::websocket::connection &)>;
        using on_close_callback =
            std::function<void(websocket::Context &,
                               crow::websocket::connection &,
                               const std::string &,
                               uint16_t)>;
        using on_message_callback =
            std::function<void(websocket::Context &,
                               crow::websocket::connection &,
                               const std::string &,
                               bool)>;

        void setup(Server *,
                   const std::string &,
                   uint64_t,
                   on_message_callback = nullptr,
                   on_error_callback = nullptr,
                   on_accept_callback = nullptr,
                   on_open_callback = nullptr,
                   on_close_callback = nullptr);

        ~WebSocket() = default;
        WebSocket() = default;

        // void _plugins() override;
        const std::size_t size_connections() const;

      private:
        Server *server_;
        std::string url_;
        websocket::Context context_;
        std::mutex mtx_;

        on_message_callback on_message_;
        on_error_callback on_error_;
        on_accept_callback on_accept_;
        on_open_callback on_open_;
        on_close_callback on_close_;

        void def_close_connection(crow::websocket::connection *,
                                  const std::string &);
        void def_message_connection(crow::websocket::connection *,
                                    const std::string &);
        void def_open_connection(crow::websocket::connection *);
        [[nodiscard]] bool def_accept_connection(const crow::request *);
        void def_error_connection(crow::websocket::connection *,
                                  const std::string &);
    };
} // namespace engine::server::gateway::websocket
