#include <engine/server/exception.hxx>
#include <engine/server/server.hxx>

namespace engine
{
    namespace server
    {
        Server::Server() : m_app(new App())
        {
        }

        void Server::setup(configuration::Configuration &p_config,
                           logging::Logging &p_log)
        {
            m_config = &p_config;
            m_log = &p_log;

            name.assign(m_config->get<std::string>("server.name"));
            bindaddr.assign(m_config->get<std::string>("server.bindaddr"));
            ssl_certificate_path.assign(
                m_config->get<std::string>("server.ssl_certificate_path"));
            concurrency = m_config->get<int64_t>("server.threads");
            port = m_config->get<int64_t>("server.port");
        }

#ifdef ENGINE_PRO
        void Server::register_plugins()
        {
            plugins::Plugins::lua.state["_server"] = this;
            plugins::Plugins::lua.state.new_usertype<Server>(
                "Server",
                "port",
                sol::readonly(&Server::port),
                "bindaddr",
                sol::readonly(&Server::bindaddr),
                "concurrency",
                sol::readonly(&Server::concurrency));
        }
#endif

        void Server::run()
        {
            m_app
                ->bindaddr(bindaddr)
#if CROW_OPENSSL
                .ssl_file(ssl_certificate_path)
#endif
                .port(port)
                .concurrency(concurrency)
                .server_name(name)
                .run();
        }

        Server &Server::operator=(const Server &p_server)
        {
            if (this != &p_server) {
                m_config = p_server.m_config;
                m_log = p_server.m_log;
                m_app = std::make_shared<App>(*p_server.m_app);

                name.assign(m_config->get<std::string>("server.name"));
                bindaddr.assign(m_config->get<std::string>("server.bindaddr"));
                ssl_certificate_path.assign(
                    m_config->get<std::string>("server.ssl_certificate_path"));
                concurrency = m_config->get<int64_t>("server.threads");
                port = m_config->get<int64_t>("server.port");
            }
            return *this;
        }

        void Server::stop()
        {
            m_app->stop();
        }

        configuration::Configuration &Server::get_config()
        {
            return *m_config;
        }

        App &Server::get()
        {
            return *m_app;
        }

        logging::Logging &Server::get_log()
        {
            return *m_log;
        }
    } // namespace server
} // namespace engine
