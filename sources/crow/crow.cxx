#include "crow.hxx"

namespace Crow
{
    CrowApi::CrowApi(const std::string p_bindaddr , const std::uint16_t p_port) : m_port(p_port),
                                                                                  m_bindaddr(p_bindaddr)
    {
        m_app.loglevel(crow::LogLevel::Info);
    }

    CrowApi::~CrowApi()
    {
    }

    void CrowApi::run()
    {
        m_app.bindaddr(m_bindaddr).port(m_port).multithreaded().run();
    }

    crow::SimpleApp &CrowApi::get_app()
    {
        return m_app;
    }

    void CrowApi::set_ssl_file(const std::string &p_pem, const std::string &p_key)
    {
        // m_app.ssl_file(p_pem, p_key);
    }
};