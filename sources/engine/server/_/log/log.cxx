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
                config_ = p_config;
                log_ = p_log;

                crow::logger::setHandler(
                    this); // define global logger for Server

                log_.create_logger(
                    config_.get("logging.type").value<std::string>().value(),
                    config_.get("server._.log.name")
                        .value<std::string>()
                        .value());

                Log::active_level(static_cast<crow::LogLevel>(
                    config_.get("server._.log.level")
                        .value<int64_t>()
                        .value()));
            }

            void Log::log(const std::string &p_message, crow::LogLevel p_level)
            {
                switch (p_level) {
                    case crow::LogLevel::Debug:
                        log_
                            .get_logger(config_.get("server._.log.name")
                                            .value<std::string>()
                                            .value())
                            ->debug("{}", p_message);
                        break;
                    case crow::LogLevel::Info:
                        log_
                            .get_logger(config_.get("server._.log.name")
                                            .value<std::string>()
                                            .value())
                            ->info("{}", p_message);
                        break;
                    case crow::LogLevel::Warning:
                        log_
                            .get_logger(config_.get("server._.log.name")
                                            .value<std::string>()
                                            .value())
                            ->warn("{}", p_message);
                        break;
                    case crow::LogLevel::Error:
                        log_
                            .get_logger(config_.get("server._.log.name")
                                            .value<std::string>()
                                            .value())
                            ->error("{}", p_message);
                        break;
                    case crow::LogLevel::Critical:
                        log_
                            .get_logger(config_.get("server._.log.name")
                                            .value<std::string>()
                                            .value())
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