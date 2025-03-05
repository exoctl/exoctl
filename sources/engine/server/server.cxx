#include <engine/bridge/exception.hxx>
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
            certfile.assign(config->get("server.ssl.certfile")
                                .value<std::string>()
                                .value());
            keyfile.assign(
                config->get("server.ssl.keyfile").value<std::string>().value());
            concurrency =
                config->get("server.threads").value<int64_t>().value();
            port = config->get("server.port").value<int64_t>().value();
        }

        void Server::tick(std::chrono::milliseconds p_milliseconds,
                          std::function<void()> p_func)
        {
            m_app->tick(p_milliseconds, p_func);
        }

        std::future<void> Server::run_async()
        {
            return m_app->bindaddr(bindaddr)
                .ssl_file(certfile, keyfile)
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
                m_app = p_server.m_app;

                certfile.assign(config->get("server.ssl.certfile")
                                    .value<std::string>()
                                    .value());
                keyfile.assign(config->get("server.ssl.keyfile")
                                   .value<std::string>()
                                   .value());
                name.assign(p_server.config->get("server.name")
                                .value<std::string>()
                                .value());
                bindaddr.assign(p_server.config->get("server.bindaddr")
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
