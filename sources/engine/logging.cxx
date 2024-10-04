#include <engine/logging.hxx>
#include <spdlog/async.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace logging
{
    Logging::Logging(parser::Toml &p_config) : m_config(p_config)
    {
        Logging::logging_active_type(
            GET_TOML_TBL_VALUE(p_config, string, "log", "type"));
        Logging::logging_active_trace(
            GET_TOML_TBL_VALUE(p_config, uint16_t, "log", "trace"));
        Logging::logging_active_level(
            GET_TOML_TBL_VALUE(p_config, uint16_t, "log", "level"));
        Logging::logging_active_console(
            GET_TOML_TBL_VALUE(p_config, bool, "log", "console"));
    }

    Logging::~Logging()
    {
    }

    void Logging::logging_active_trace(const uint16_t p_level)
    {
        m_logger->flush_on(static_cast<spdlog::level::level_enum>(p_level));
    }

    void Logging::logging_active_level(const uint16_t p_level)
    {
        m_logger->set_level(static_cast<spdlog::level::level_enum>(p_level));
    }

    void Logging::logging_active_type(const std::string &p_type)
    {
        m_logger = [&]() -> std::shared_ptr<spdlog::logger> {
            if (p_type == "day") {
                return spdlog::daily_logger_mt<spdlog::async_factory>(
                    "day",
                    GET_TOML_TBL_VALUE(m_config, string, "log", "name"),
                    GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "hours"),
                    GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "minutes"),
                    false,
                    GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "max_files"));
            } else if (p_type == "rotation") {
                return spdlog::rotating_logger_mt<spdlog::async_factory>(
                    "rotation",
                    GET_TOML_TBL_VALUE(m_config, string, "log", "name"),
                    GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "max_size"),
                    GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "max_files"));
            }

            /* default logger */
            return spdlog::basic_logger_mt<spdlog::async_factory>(
                "basic", GET_TOML_TBL_VALUE(m_config, string, "log", "name"));
        }();
    }

    void Logging::logging_active_console(const bool p_console)
    {
        if (p_console) {
            auto console_sink =
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            m_logger->sinks().push_back(console_sink);
        }
    }

} // namespace Logging
