#include <engine/server/gateway/websocket/context/context.hxx>

namespace engine::server::gateway::websocket
{
    Context::Context() : context_(0)
    {
    }

    const void Context::erase(crow::websocket::connection *p_conn)
    {
        context_.erase(p_conn);
    }

    void Context::broadcast_text(crow::websocket::connection *p_conn,
                                 const std::string p_msg) const
    {
        if (context_.find(p_conn) != context_.end())
            p_conn->send_text(p_msg);
    }

    void Context::broadcast_binary(crow::websocket::connection *p_conn,
                                   const std::string p_msg) const
    {
        if (context_.find(p_conn) != context_.end())
            p_conn->send_binary(p_msg);
    }

    const void Context::add(crow::websocket::connection *p_conn)
    {
        context_.insert(p_conn);
    }

    const std::size_t Context::size() const
    {
        return context_.size();
    }

    const std::string Context::get_remote_ip(
        crow::websocket::connection *p_conn) const
    {
        return (context_.find(p_conn) != context_.end())
                   ? p_conn->get_remote_ip()
                   : "";
    }

    const std::string Context::get_subprotocol(
        crow::websocket::connection *p_conn) const
    {
        return (context_.find(p_conn) != context_.end())
                   ? p_conn->get_subprotocol()
                   : "";
    }

    const void Context::close(crow::websocket::connection *p_conn,
                              uint16_t p_code,
                              const std::string &p_message)
    {
        if (context_.find(p_conn) != context_.end()) {
            p_conn->close(p_message, p_code);
            Context::erase(p_conn);
        }
    }
} // namespace engine::server::gateway::websocket
