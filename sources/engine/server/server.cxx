#include <engine/bridge/exception.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>

namespace engine
{
    namespace server
    {
        void Server::setup(configuration::Configuration &p_config,
                           logging::Logging &p_log)
        {
            config = &p_config;
            log = &p_log;

            this->get_middleware<middlewares::cors::Cors>().setup(*config);

            name.assign(
                config->get("server.name").value<std::string>().value());
            baddr.assign(
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

        void Server::load()
        {
            log->info("Server configured with name: {}, address: {}, port: {}, "
                      "threads: {}, SSL: {}",
                      name,
                      baddr,
                      port,
                      concurrency,
                      ssl_enable ? "enabled" : "disabled");

            log->info("Loading middlewares...");
            this->get_middleware<middlewares::cors::Cors>().load();
        }

        std::future<void> Server::start()
        {
            log->info("Preparing to run server asynchronously...");

            this->bindaddr(baddr)
                .port(port)
                .concurrency(concurrency)
                .server_name(name);

            if (ssl_enable) {
                log->info("SSL enabled. Certfile: '{}', Keyfile: '{}'",
                          certfile,
                          keyfile);
                if (!keyfile.empty()) {
                    this->ssl_file(certfile, keyfile);
                } else {
                    this->ssl_file(certfile);
                }
            }

            return this->run_async();
        }

        Server &Server::operator=(const Server &p_server)
        {
            if (this != &p_server) {
                log = p_server.log;
                config = p_server.config;

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
                baddr.assign(p_server.config->get("server.bindaddr")
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

        void Server::end()
        {
            this->stop();
        }
    } // namespace server
} // namespace engine
