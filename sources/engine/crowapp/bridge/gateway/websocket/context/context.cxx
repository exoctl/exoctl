#include <engine/crowapp/bridge/gateway/websocket/context/context.hxx>

namespace engine
{
    namespace crowapp
    {
        namespace bridge
        {
            namespace gateway
            {
                namespace websocket
                {
                    Context::Context(configuration::Configuration &p_config)
                        : m_context(0), m_config(p_config)
                    {
                    }

                    Context::~Context()
                    {
                    }

                    const void Context::erase(
                        crow::websocket::connection *p_conn)
                    {
                        m_context.erase(p_conn);
                    }

                    const void Context::broadcast(
                        crow::websocket::connection *p_conn,
                        const std::string p_msg) const
                    {
                        if (m_context.find(p_conn) != m_context.end())
                            p_conn->send_text(p_msg);
                    }

                    const void Context::add(crow::websocket::connection *p_conn)
                    {
                        m_context.insert(p_conn);
                    }

                    const std::size_t Context::size() const
                    {
                        return m_context.size();
                    }

                    const std::string Context::get_remote_ip(
                        crow::websocket::connection *p_conn) const
                    {
                        return (m_context.find(p_conn) != m_context.end())
                                   ? p_conn->get_remote_ip()
                                   : nullptr;
                    }

                    const bool Context::check_whitelist(
                        const crow::request *p_request)
                    {
                        for (const auto &list :
                             m_config.get_crowapp().server.context.whitelist)
                            if (const auto str = list.as_string()) {
                                if (p_request->remote_ip_address == str->get())
                                    return true;
                            }

                        return false;
                    }
                } // namespace websocket
            } // namespace gateway
        } // namespace bridge
    } // namespace crowapp
} // namespace engine