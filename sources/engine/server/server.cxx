#include <engine/server/exception.hxx>
#include <engine/server/server.hxx>

namespace engine
{
    namespace server
    {
        void Server::setup(configuration::Configuration &p_config,
                           logging::Logging &p_log)
        {
            m_config = p_config;
            m_log = p_log;

            concurrency = m_config.get_server().threads;
            bindaddr = m_config.get_server().bindaddr;
            port = m_config.get_server().port;
            ssl_certificate_path = m_config.get_server().ssl_certificate_path;
        }

#ifdef ENGINE_PRO
        void Server::register_plugins()
        {
            plugins::Plugins::lua.state["server"] = this;
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
                .run();
        }

        Server &Server::operator=(const Server &p_server)
        {
            if (this != &p_server) {
                m_config = p_server.m_config;
                m_log = p_server.m_log;
                m_app = std::make_shared<App>(*p_server.m_app);

                concurrency = p_server.m_config.get_server().threads;
                bindaddr = p_server.m_config.get_server().bindaddr;
                port = p_server.m_config.get_server().port;
                ssl_certificate_path =
                    p_server.m_config.get_server().ssl_certificate_path;
            }
            return *this;
        }

        void Server::stop()
        {
            m_app->stop();
        }

        configuration::Configuration &Server::get_config()
        {
            return m_config;
        }

        App &Server::get()
        {
            return *m_app;
        }

        logging::Logging &Server::get_log()
        {
            return m_log;
        }
    } // namespace server
} // namespace engine
