#include <engine/crow/crow.hxx>
#include <engine/crow/crow_exception.hxx>

namespace Crow
{
    CrowApp::CrowApp(Parser::Toml &p_config, Logging::Log &p_log)
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
        TRY_BEGIN()
        m_app
            .bindaddr(m_bindaddr)
#if CROW_OPENSSL
            .ssl_file(m_ssl_file_pem)
#endif
            .port(m_port)
            .concurrency(m_threads)
            .run();
        TRY_END()
        CATCH(std::runtime_error, {
            LOG(m_log, error, "An exception runtime occurred: {}", e.what());

            throw Crow::CrowException::Abort("Initialization failed: " +
                                             std::string(e.what()));
        })
        CATCH(std::exception, {
            LOG(m_log, error, "An exception occurred: {}", e.what());

            throw Crow::CrowException::ParcialAbort("Failed: " +
                                                    std::string(e.what()));
        })
    }

    void CrowApp::crow_stop()
    {
        m_app.multithreaded().stop();
    }

    const uint16_t CrowApp::crow_get_concurrency()
    {
        return m_threads;
    }

    Parser::Toml &CrowApp::crow_get_config()
    {
        return m_config;
    }

    crow::SimpleApp &CrowApp::crow_get_app()
    {
        return m_app;
    }

    Logging::Log &CrowApp::crow_get_log()
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
}; // namespace Crow