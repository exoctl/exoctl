#pragma once

#include <crow.h>
#include <engine/server/bridge/gateway/web/middlewares/jwtauth.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <string>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            namespace gateway
            {
                template <typename... Args> class Web
                {
                  public:
                    using on_request_callback = std::function<crow::response(
                        const crow::request &, Args...)>;

                    Web(Server &p_server,
                        const std::string &p_url,
                        on_request_callback on_request)
                        : m_server(p_server), m_url(p_url),
                          m_on_request(on_request)
                    {
                        LOG(m_server.get_log(),
                            info,
                            "Creating HTTP route for URL: '{}'",
                            m_url);

                        m_server.get()
                            .route_dynamic(m_url)
                            .middlewares<crow::App<middleware::web::JWTAuth>,
                                         middleware::web::JWTAuth>()(
                                m_on_request);
                        m_server.get().validate();
                    }

                    ~Web() = default;

                  private:
                    Server &m_server;
                    std::string m_url;
                    on_request_callback m_on_request;
                };
            } // namespace gateway
        } // namespace bridge
    } // namespace server
} // namespace engine