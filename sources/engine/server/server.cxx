#include <engine/server/exception.hxx>
#include <engine/server/gateway/crow/crow.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>

namespace engine
{
    namespace server
    {
        Server::Server() : m_app(std::make_shared<App>())
        {
        }

        void Server::setup(configuration::Configuration &p_config,
                           logging::Logging &p_log)
        {
            config = &p_config;
            log = &p_log;

            name.assign(
                config->get("server.name").value<std::string>().value());
            bindaddr.assign(
                config->get("server.bindaddr").value<std::string>().value());
            ssl_certificate_path.assign(
                config->get("server.ssl_certificate_path")
                    .value<std::string>()
                    .value());
            concurrency =
                config->get("server.threads").value<int64_t>().value();
            port = config->get("server.port").value<int64_t>().value();
        }

#ifdef ENGINE_PRO
        void Server::register_plugins()
        {
            engine::server::gateway::Crow::plugins();
            engine::server::gateway::Web::plugins();
            // engine::server::gateway::WebSocket::plugins();

            plugins::Plugins::lua.state.new_usertype<Server>(
                "Server",
                sol::constructors<server::Server()>(),
                "setup",
                Server::setup,
                "run_async",
                Server::run_async,
                "stop",
                Server::stop,
                "port",
                sol::readonly(&Server::port),
                "bindaddr",
                sol::readonly(&Server::bindaddr),
                "concurrency",
                sol::readonly(&Server::concurrency));
        }
#endif

        std::future<void> Server::run_async()
        {
            return m_app
                ->bindaddr(bindaddr)
#if CROW_OPENSSL
                .ssl_file(ssl_certificate_path)
#endif
                .port(port)
                .concurrency(concurrency)
                .server_name(name)
                .run_async();
        }

        Server &Server::operator=(const Server &p_server)
        {
            if (this != &p_server) {
                config = p_server.config;
                log = p_server.log;
                m_app = std::make_shared<App>(*p_server.m_app);

                name.assign(p_server.config->get("server.name")
                                .value<std::string>()
                                .value());
                bindaddr.assign(p_server.config->get("server.bindaddr")
                                    .value<std::string>()
                                    .value());
                ssl_certificate_path.assign(
                    p_server.config->get("server.ssl_certificate_path")
                        .value<std::string>()
                        .value());
                concurrency = p_server.config->get("server.threads")
                                  .value<int64_t>()
                                  .value();
                port = p_server.config->get("server.port")
                           .value<int64_t>()
                           .value();
            }
            return *this;
        }

        void Server::stop()
        {
            m_app->stop();
        }

        App &Server::get()
        {
            return *m_app;
        }

    } // namespace server
} // namespace engine
