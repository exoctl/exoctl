#include "crow.hxx"

namespace Crow
{
    CrowApi::CrowApi(std::uint16_t p_port) : m_port(p_port)
    {
        m_app.loglevel(crow::LogLevel::Info);
    }
    CrowApi::~CrowApi()
    {
    }

    void CrowApi::run()
    {
        m_app.port(m_port).multithreaded().run();
    }

    crow::SimpleApp &CrowApi::get_app()
    {
        return m_app;
    }

};