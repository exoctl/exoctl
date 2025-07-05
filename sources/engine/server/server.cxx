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

            m_app->get_middleware<middlewares::cors::Cors>().setup(*config);

            name.assign(
                config->get("server.name").value<std::string>().value());
            bindaddr.assign(
                config->get("server.bindaddr").value<std::string>().value());
            certfile.assign(config->get("server.ssl.certfile")
                                .value<std::string>()
                                .value());
            ssl_enable = config->get("server.ssl.enable").value<bool>().value();
            keyfile.assign(
                config->get("server.ssl.keyfile").value<std::string>().value());
            concurrency =
                config->get("server.threads").value<int64_t>().value();
            port = config->get("server.port").value<int64_t>().value();
        }

        void Server::tick(std::chrono::milliseconds p_milliseconds,
                          std::function<void()> p_func)
        {
            log->info("Registering tick with interval: {}ms",
                      p_milliseconds.count());
            m_app->tick(p_milliseconds, p_func);
        }

        void Server::load()
        {
            log->info("Server configured with name: {}, address: {}, port: {}, "
                      "threads: {}, SSL: {}",
                      name,
                      bindaddr,
                      port,
                      concurrency,
                      ssl_enable ? "enabled" : "disabled");

            log->info("Loading middlewares...");
            m_app->get_middleware<middlewares::cors::Cors>().load();
        }

        std::future<void> Server::run_async()
        {
            log->info("Preparing to run server asynchronously...");

            m_app->bindaddr(bindaddr)
                .port(port)
                .concurrency(concurrency)
                .server_name(name);

            if (ssl_enable) {
                log->info("SSL enabled. Certfile: '{}', Keyfile: '{}'",
                          certfile,
                          keyfile);
                if (!keyfile.empty()) {
                    m_app->ssl_file(certfile, keyfile);
                } else {
                    m_app->ssl_file(certfile);
                }
            }

            return m_app->run_async();
        }

        Server &Server::operator=(const Server &p_server)
        {
            if (this != &p_server) {
                log = p_server.log;
                config = p_server.config;
                m_app = p_server.m_app;

                ssl_enable = p_server.config->get("server.ssl.enable")
                                 .value<bool>()
                                 .value();
                certfile.assign(p_server.config->get("server.ssl.certfile")
                                    .value<std::string>()
                                    .value());
                keyfile.assign(p_server.config->get("server.ssl.keyfile")
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
