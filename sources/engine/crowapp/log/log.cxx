#include <engine/crowapp/log/log.hxx>

namespace engine
{
    namespace crowapp
    {
        Log::Log(CrowApp &p_crow) : m_crowapp(p_crow)
        {
            crow::logger::setHandler(this); // define global logger for CrowApp
            Log::active_level(static_cast<crow::LogLevel>(
                m_crowapp.get_config().get_crowapp().log.level));
        }

        Log::~Log()
        {
        }

        void Log::log(std::string p_message, crow::LogLevel p_level)
        {
            switch (p_level) {
                case crow::LogLevel::Debug:
                    LOG(m_crowapp.get_log(), debug, "{}", p_message);
                    break;
                case crow::LogLevel::Info:
                    LOG(m_crowapp.get_log(), info, "{}", p_message);
                    break;
                case crow::LogLevel::Warning:
                    LOG(m_crowapp.get_log(), warn, "{}", p_message);
                    break;
                case crow::LogLevel::Error:
                    LOG(m_crowapp.get_log(), error, "{}", p_message);
                    break;
                case crow::LogLevel::Critical:
                    LOG(m_crowapp.get_log(), critical, "{}", p_message);
                    break;
            }
        }

        void Log::active_level(crow::LogLevel p_level)
        {
            m_crowapp.get_app().loglevel(p_level);
        }
    } // namespace crowapp
} // namespace engine