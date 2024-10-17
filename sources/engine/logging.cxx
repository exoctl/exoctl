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
            Logging::active_type(m_config.get_logging().type);
            Logging::active_trace(m_config.get_logging().trace.interval);
            Logging::active_level(m_config.get_logging().level);
            Logging::active_console(m_config.get_logging().console);
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

        void Logging::active_type(const std::string &p_type)
        {
            m_logger = create_logger(p_type, p_type);
        }

        std::shared_ptr<spdlog::logger> Logging::create_logger(
            const std::string &type, const std::string &name)
        {
            if (type == "daily") {
                return spdlog::daily_logger_mt<spdlog::async_factory>(
                    name,
                    m_config.get_logging().name,
                    m_config.get_logging().daily_settings.hours,
                    m_config.get_logging().daily_settings.minutes,
                    false,
                    m_config.get_logging().daily_settings.max_size);
            } else if (type == "rotation") {
                return spdlog::rotating_logger_mt<spdlog::async_factory>(
                    name,
                    m_config.get_logging().name,
                    m_config.get_logging().rotation_settings.max_size,
                    m_config.get_logging().rotation_settings.max_files);
            }

            /* default logger */
            return spdlog::basic_logger_mt<spdlog::async_factory>(
                name, m_config.get_logging().name);
        }

        void Logging::active_console(bool p_console)
        {
            if (p_console) {
                auto console_sink =
                    std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
                m_logger->sinks().push_back(console_sink);
            }
        }
    } // namespace logging
} // namespace engine