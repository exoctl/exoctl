#include <engine/log.hxx>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

namespace Logging
{
Log::Log(Parser::Toml &p_config) : m_config(p_config)
{
    Log::log_active_type(GET_TOML_TBL_VALUE(p_config, string, "log", "type"));
    Log::log_active_trace(
        GET_TOML_TBL_VALUE(p_config, uint16_t, "log", "trace"));
    Log::log_active_level(
        GET_TOML_TBL_VALUE(p_config, uint16_t, "log", "level"));
}

Log::~Log() {}

const void Log::log_active_trace(const uint16_t p_level)
{
    m_logger->flush_on(static_cast<spdlog::level::level_enum>(p_level));
}

const void Log::log_active_level(const uint16_t p_level)
{
    m_logger->set_level(static_cast<spdlog::level::level_enum>(p_level));
}

const void Log::log_active_type(const std::string &p_type)
{
    m_logger = [&]() -> std::shared_ptr<spdlog::logger>
    {
        if (p_type == "day")
        {
            return spdlog::daily_logger_mt<spdlog::async_factory>(
                "day",
                GET_TOML_TBL_VALUE(m_config, string, "log", "name"),
                GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "hours"),
                GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "minutes"),
                false,
                GET_TOML_TBL_VALUE(m_config, uint16_t, "log", "max_files"));
        }
        else if (p_type == "rotation")
        {
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
} // namespace Logging