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

                m_log.create_logger(m_config.get_logging().type,
                                    m_config.get_crowapp().log.name);

                Log::active_level(static_cast<crow::LogLevel>(
                    m_config.get_crowapp().log.level));
            }

            Log::~Log()
            {
            }

            void Log::log(std::string p_message, crow::LogLevel p_level)
            {
                switch (p_level) {
                    case crow::LogLevel::Debug:
                        m_log.get_logger(m_config.get_crowapp().log.name)
                            ->debug("{}", p_message);
                        break;
                    case crow::LogLevel::Info:
                        m_log.get_logger(m_config.get_crowapp().log.name)
                            ->info("{}", p_message);
                        break;
                    case crow::LogLevel::Warning:
                        m_log.get_logger(m_config.get_crowapp().log.name)
                            ->warn("{}", p_message);
                        break;
                    case crow::LogLevel::Error:
                        m_log.get_logger(m_config.get_crowapp().log.name)
                            ->error("{}", p_message);
                        break;
                    case crow::LogLevel::Critical:
                        m_log.get_logger(m_config.get_crowapp().log.name)
                            ->critical("{}", p_message);
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