#include <engine/crowapp/log/log.hxx>

namespace crowapp
{

    Log::Log(CrowApp &p_crow) : m_log(p_crow.get_log()), m_crow(p_crow)
    {
        crow::logger::setHandler(this); // define global logger for CrowApp
    }

    Log::~Log()
    {
    }

    void Log::log(std::string p_message, crow::LogLevel p_level)
    {
        switch (p_level) {
            case crow::LogLevel::Debug:
                LOG(m_log, debug, "{}", p_message);
                break;
            case crow::LogLevel::Info:
                LOG(m_log, info, "{}", p_message);
                break;
            case crow::LogLevel::Warning:
                LOG(m_log, warn, "{}", p_message);
                break;
            case crow::LogLevel::Error:
                LOG(m_log, error, "{}", p_message);
                break;
            case crow::LogLevel::Critical:
                LOG(m_log, critical, "{}", p_message);
                break;
        }
    }

    void Log::active_level(crow::LogLevel p_level)
    {
        m_crow.get_app().loglevel(p_level);
    }

} // namespace crowapp