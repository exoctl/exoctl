#include <engine/server/exception.hxx>
#include <engine/server/server.hxx>

namespace engine
{
    namespace server
    {
        Server::Server(configuration::Configuration &p_config,
                       logging::Logging &p_log)
            : m_config(p_config), m_log(p_log),
              concurrency(m_config.get_server().threads),
              bindaddr(m_config.get_server().bindaddr),
              port(m_config.get_server().port),
              ssl_certificate_path(m_config.get_server().ssl_certificate_path)
        {
        }

        void Server::run()
        {
            m_app
                .bindaddr(bindaddr)
#if CROW_OPENSSL
                .ssl_file(ssl_certificate_path)
#endif
                .port(port)
                .concurrency(concurrency)
                .run();
        }

        void Server::stop()
        {
            m_app.stop();
        }

        configuration::Configuration &Server::get_config()
        {
            return m_config;
        }

        App &Server::get()
        {
            return m_app;
        }

        logging::Logging &Server::get_log()
        {
            return m_log;
        }
    }; // namespace server
} // namespace engine