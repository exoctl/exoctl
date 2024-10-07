#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/exception.hxx>

namespace crowapp
{
    CrowApp::CrowApp(configuration::Configuration &p_config,
                     logging::Logging &p_log)
        : m_config(p_config), m_log(p_log)
    {
    }

    CrowApp::~CrowApp()
    {
    }

    void CrowApp::run()
    {
        m_app
            .bindaddr(m_config.get_crowapp().bindaddr)
#if CROW_OPENSSL
            .ssl_file(m_config.get_crowapp().ssl_file_pem)
#endif
            .port(m_config.get_crowapp().port)
            .concurrency(m_config.get_crowapp().threads)
            .run();
    }

    void CrowApp::stop()
    {
        m_app.stop();
    }

    const uint16_t CrowApp::get_concurrency()
    {
        return m_config.get_crowapp().threads;
    }

    configuration::Configuration &CrowApp::get_config()
    {
        return m_config;
    }

    crow::SimpleApp &CrowApp::get_app()
    {
        return m_app;
    }

    logging::Logging &CrowApp::get_log()
    {
        return m_log;
    }

    const std::string &CrowApp::get_bindaddr()
    {
        return m_config.get_crowapp().bindaddr;
    }

    const uint16_t &CrowApp::get_port()
    {
        return m_config.get_crowapp().port;
    }
}; // namespace crowapp