#pragma once

#include <crow.h>
#include <engine/crow/crow.hxx>
#include <engine/crow/routes/websocket/conn/conn.hxx>
#include <functional>
#include <string>

namespace Crow
{
class WebSocket
{
  public:
    using on_error_callback = std::function<void(
        Context &, crow::websocket::connection &, const std::string &)>;
    using on_accept_callback =
        std::function<bool(Context &, const crow::request &, void **)>;
    using on_open_callback =
        std::function<void(Context &, crow::websocket::connection &)>;
    using on_close_callback = std::function<void(Context &,
                                                 crow::websocket::connection &,
                                                 const std::string &,
                                                 uint16_t)>;
    using on_message_callback = std::function<void(
        Context &, crow::websocket::connection &, const std::string &, bool)>;

    WebSocket(CrowApp &,
              const std::string &,
              on_message_callback = nullptr,
              on_error_callback = nullptr,
              on_accept_callback = nullptr,
              on_open_callback = nullptr,
              on_close_callback = nullptr);

    ~WebSocket();

  private:
    CrowApp &m_crow;
    std::string m_url;
    Context m_context;
    std::mutex m_mtx;
    on_message_callback m_on_message;
    on_error_callback m_on_error;
    on_accept_callback m_on_accept;
    on_open_callback m_on_open;
    on_close_callback m_on_close;

    void websocket_def_close_connection(crow::websocket::connection *,
                                        const std::string &);
    void websocket_def_open_connection(crow::websocket::connection *);
    bool websocket_def_onaccept_connection(const crow::request *);
};
} // namespace Crow
