#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/exception.hxx>

namespace crowapp
{
    CrowApp::CrowApp(parser::Toml &p_config, logging::Logging &p_log)
        : m_config(p_config), m_log(p_log),
          m_port(GET_TOML_TBL_VALUE(p_config, uint16_t, "crow", "port")),
          m_threads(GET_TOML_TBL_VALUE(p_config, uint16_t, "crow", "threads")),
#if CROW_OPENSSL
          m_ssl_file_pem(
              GET_TOML_TBL_VALUE(p_config, string, "crow", "ssl_file_pem")),
#endif
          m_bindaddr(GET_TOML_TBL_VALUE(p_config, string, "crow", "bindaddr"))
    {
    }

    CrowApp::~CrowApp()
    {
    }

    void CrowApp::crow_run()
    {
        m_app
            .bindaddr(m_bindaddr)
#if CROW_OPENSSL
            .ssl_file(m_ssl_file_pem)
#endif
            .port(m_port)
            .concurrency(m_threads)
            .run();
    }

    void CrowApp::crow_stop()
    {
        m_app.stop();
    }

    const uint16_t CrowApp::crow_get_concurrency()
    {
        return m_threads;
    }

    parser::Toml &CrowApp::crow_get_config()
    {
        return m_config;
    }

    crow::SimpleApp &CrowApp::crow_get_app()
    {
        return m_app;
    }

    logging::Logging &CrowApp::crow_get_log()
    {
        return m_log;
    }

    const std::string &CrowApp::crow_bindaddr()
    {
        return m_bindaddr;
    }

    const uint16_t &CrowApp::crow_port()
    {
        return m_port;
    }
}; // namespace crowapp