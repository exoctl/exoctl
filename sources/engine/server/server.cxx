#include <engine/server/server.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    namespace server
    {
        Server::Server(configuration::Configuration &p_config,
                         logging::Logging &p_log)
            : m_config(p_config), m_log(p_log)
        {
        }

        void Server::run()
        {
            m_app
                .bindaddr(m_config.get().bindaddr)
#if CROW_OPENSSL
                .ssl_file(m_config.get().ssl_certificate_path)
#endif
                .port(m_config.get().port)
                .concurrency(m_config.get().threads)
                .run();
        }

        void Server::stop()
        {
            m_app.stop();
        }

        const uint16_t Server::get_concurrency()
        {
            return m_config.get().threads;
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

        const std::string &Server::get_bindaddr()
        {
            return m_config.get().bindaddr;
        }

        const uint16_t &Server::get_port()
        {
            return m_config.get().port;
        }
    }; // namespace server
} // namespace engine