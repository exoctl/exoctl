#include <engine/logging.hxx>
#include <memory>
#include <spdlog/async.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <string>

namespace engine
{
    namespace logging
    {
        Logging::Logging(configuration::Configuration &p_config)
            : m_config(p_config)
        {
        }

        Logging::~Logging() = default;

        spdlog::logger &Logging::get()
        {
            return *m_logger;
        }

        void Logging::load()
        {
            Logging::active_instance(m_config.get_logging().type,
                                     m_config.get_logging().name);
            Logging::active_trace(m_config.get_logging().trace.interval);
            Logging::active_level(m_config.get_logging().level);
            Logging::active_pattern(m_config.get_logging().pattern);
        }

        void Logging::active_trace(const uint16_t p_level)
        {
            m_logger->flush_on(static_cast<spdlog::level::level_enum>(p_level));
        }

        void Logging::active_level(const uint16_t p_level)
        {
            m_logger->set_level(
                static_cast<spdlog::level::level_enum>(p_level));
        }

        void Logging::active_pattern(const std::string &p_pattern)
        {
            m_logger->set_pattern(p_pattern);
        }

        void Logging::active_instance(const std::string &p_type,
                                      const std::string &p_name)
        {
            m_logger = create_logger(p_type, p_name);
        }

        std::shared_ptr<spdlog::logger> Logging::create_logger(
            const std::string &type, const std::string &name)
        {
            std::vector<spdlog::sink_ptr> sinks;

            if (type == "daily") {
                sinks.push_back(
                    std::make_shared<spdlog::sinks::daily_file_sink_mt>(
                        m_config.get_logging().filepath,
                        m_config.get_logging().daily_settings.hours,
                        m_config.get_logging().daily_settings.minutes,
                        false,
                        m_config.get_logging().daily_settings.max_size));
            } else if (type == "rotation") {
                sinks.push_back(
                    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                        m_config.get_logging().filepath,
                        m_config.get_logging().rotation_settings.max_size,
                        m_config.get_logging().rotation_settings.max_files));
            } else {
                sinks.push_back(
                    std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                        m_config.get_logging().filepath, true));
            }

            if (m_config.get_logging().console) {
                auto console_sink =
                    std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

                if (std::none_of(
                        sinks.begin(),
                        sinks.end(),
                        [](const spdlog::sink_ptr &s) {
                            return dynamic_cast<
                                       spdlog::sinks::stdout_color_sink_mt *>(
                                       s.get()) != nullptr;
                        })) {
                    sinks.push_back(console_sink);
                }
            }

            auto logger = std::make_shared<spdlog::logger>(
                name, sinks.begin(), sinks.end());
            spdlog::register_logger(logger);

            return logger;
        }
    } // namespace logging
} // namespace engine