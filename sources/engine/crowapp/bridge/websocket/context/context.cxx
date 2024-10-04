#include <engine/crowapp/bridge/websocket/context/context.hxx>

namespace crowapp
{
    namespace bridge
    {
        namespace websocket
        {
            Context::Context(parser::Toml &p_config)
                : m_context(0), m_config(p_config),
                  m_whitelist(GET_TOML_TBL_VALUE(
                      m_config, array, "crow", "websocket_context_whitelist"))
            {
            }

            Context::~Context()
            {
            }

            const void Context::context_erase(crow::websocket::connection *p_conn)
            {
                m_context.erase(p_conn);
            }

            const void Context::context_broadcast(
                crow::websocket::connection *p_conn,
                const std::string p_msg) const
            {
                if (m_context.find(p_conn) != m_context.end())
                    p_conn->send_text(p_msg);
            }

            const void Context::context_add(crow::websocket::connection *p_conn)
            {
                m_context.insert(p_conn);
            }

            const std::size_t Context::context_size() const
            {
                return m_context.size();
            }

            const std::string Context::context_get_remote_ip(
                crow::websocket::connection *p_conn) const
            {
                return (m_context.find(p_conn) != m_context.end())
                           ? p_conn->get_remote_ip()
                           : nullptr;
            }

            const bool Context::context_check_whitelist(
                const crow::request *p_request)
            {
                for (const auto &list : m_whitelist)
                    if (const auto str = list.as_string()) {
                        if (p_request->remote_ip_address == str->get())
                            return true;
                    }

                return false;
            }
        } // namespace websocket
    } // namespace bridge
} // namespace crowapp