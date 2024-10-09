#include <engine/logging.hxx>
#include <spdlog/async.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace logging
{
    Logging::Logging(configuration::Configuration &p_config)
        : m_config(p_config)
    {
        Logging::active_type(m_config.get_log().type);
        Logging::active_trace(m_config.get_log().trace.interval);
        Logging::active_level(m_config.get_log().level);
        Logging::active_console(m_config.get_log().console);
    }

    Logging::~Logging()
    {
    }

    void Logging::active_trace(const uint16_t p_level)
    {
        m_logger->flush_on(static_cast<spdlog::level::level_enum>(p_level));
    }

    void Logging::active_level(const uint16_t p_level)
    {
        m_logger->set_level(static_cast<spdlog::level::level_enum>(p_level));
    }

    void Logging::active_type(const std::string &p_type)
    {
        m_logger = [&]() -> std::shared_ptr<spdlog::logger> {
            if (p_type == "day") {
                return spdlog::daily_logger_mt<spdlog::async_factory>(
                    "day",
                    m_config.get_log().name,
                    m_config.get_log().daily_settings.hours,
                    m_config.get_log().daily_settings.minutes,
                    false,
                    m_config.get_log().daily_settings.max_size);
            } else if (p_type == "rotation") {
                return spdlog::rotating_logger_mt<spdlog::async_factory>(
                    "rotation",
                    m_config.get_log().name,
                    m_config.get_log().rotation_settings.max_size,
                    m_config.get_log().rotation_settings.max_files);
            }

            /* default logger */
            return spdlog::basic_logger_mt<spdlog::async_factory>(
                "basic", m_config.get_log().name);
        }();
    }

    void Logging::active_console(const bool p_console)
    {
        if (p_console) {
            auto console_sink =
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            m_logger->sinks().push_back(console_sink);
        }
    }

} // namespace logging
