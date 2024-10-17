#include "crow/logging.h"
#include <engine/crowapp/_/log/log.hxx>

namespace engine
{
    namespace crowapp
    {
        namespace _
        {
            Log::Log(configuration::Configuration &p_config,
                     logging::Logging &p_log)
                : m_config(p_config), m_log(p_log)
            {
                crow::logger::setHandler(
                    this); // define global logger for CrowApp
                Log::active_level(static_cast<crow::LogLevel>(
                    m_config.get_crowapp().log.level));
            }

            Log::~Log()
            {
                crow::logger::setHandler(nullptr); // restore handle
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
                crow::logger::setLogLevel(p_level);
            }
        } // namespace _
    } // namespace crowapp
} // namespace engine