#include <engine/server/gateway/web/web.hxx>

namespace engine::server::gateway
{
    void Web::setup(Server &p_server,
                    const std::string &p_url,
                    on_request_callback on_request,
                    const std::vector<crow::HTTPMethod> &methods)
    {
        m_server = &p_server;
        m_url = p_url;
        m_on_request = std::move(on_request);

        m_server->log->info("Creating HTTP route for URL: '{}' with {} methods",
                            m_url,
                            methods.size());

        auto &route = m_server->get().route_dynamic(m_url);

        if (!methods.empty()) {
            switch (methods.size()) {
                case 1:
                    route.methods(methods[0]);
                    break;
                case 2:
                    route.methods(methods[0], methods[1]);
                    break;
                case 3:
                    route.methods(methods[0], methods[1], methods[2]);
                    break;
                case 4:
                    route.methods(
                        methods[0], methods[1], methods[2], methods[3]);
                    break;
                case 5:
                default:
                    route.methods(methods[0],
                                  methods[1],
                                  methods[2],
                                  methods[3],
                                  methods[4]);
                    break;
            }
        } else {
            route.methods(crow::HTTPMethod::GET);
        }

        route(m_on_request);
        route.validate();
    }
} // namespace engine::server::gateway
