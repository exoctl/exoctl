#pragma once

#include <crow.h>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/websocket/context/context.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <mutex>
#include <string>

namespace engine::server::gateway
{
    class WebSocket
#ifdef ENGINE_PRO
    // : public interface::ISubPlugins<WebSocket>
#endif
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

        void setup(Server &,
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
        Server *m_server;
        std::string m_url;
        websocket::Context m_context;
        std::mutex m_mtx;

        on_message_callback m_on_message;
        on_error_callback m_on_error;
        on_accept_callback m_on_accept;
        on_open_callback m_on_open;
        on_close_callback m_on_close;

        void def_close_connection(crow::websocket::connection *,
                                  const std::string &);
        void def_message_connection(crow::websocket::connection *,
                                    const std::string &);
        void def_open_connection(crow::websocket::connection *);
        [[nodiscard]] bool def_accept_connection(const crow::request *);
        void def_error_connection(crow::websocket::connection *,
                                  const std::string &);
    };
} // namespace engine::server::gateway
