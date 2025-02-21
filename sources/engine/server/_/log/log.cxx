#include <engine/server/_/log/log.hxx>

namespace engine
{
    namespace server
    {
        namespace _
        {
            void Log::setup(configuration::Configuration &p_config,
                            logging::Logging &p_log)
            {
                m_config = p_config;
                m_log = p_log;

                crow::logger::setHandler(
                    this); // define global logger for Server

                m_log.create_logger(
                    m_config.get<std::string>("logging.type"),
                    m_config.get<std::string>("server._.log.name"));

                Log::active_level(static_cast<crow::LogLevel>(
                    m_config.get<int64_t>("server._.log.level")));
            }

            void Log::log(std::string p_message, crow::LogLevel p_level)
            {
                switch (p_level) {
                    case crow::LogLevel::Debug:
                        m_log
                            .get_logger(
                                m_config.get<std::string>("server._.log.name"))
                            ->debug("{}", p_message);
                        break;
                    case crow::LogLevel::Info:
                        m_log
                            .get_logger(
                                m_config.get<std::string>("server._.log.name"))
                            ->info("{}", p_message);
                        break;
                    case crow::LogLevel::Warning:
                        m_log
                            .get_logger(
                                m_config.get<std::string>("server._.log.name"))
                            ->warn("{}", p_message);
                        break;
                    case crow::LogLevel::Error:
                        m_log
                            .get_logger(
                                m_config.get<std::string>("server._.log.name"))
                            ->error("{}", p_message);
                        break;
                    case crow::LogLevel::Critical:
                        m_log
                            .get_logger(
                                m_config.get<std::string>("server._.log.name"))
                            ->critical("{}", p_message);
                        break;
                }
            }

            void Log::active_level(crow::LogLevel p_level)
            {
                crow::logger::setLogLevel(p_level);
            }
        } // namespace _
    } // namespace server
} // namespace engine