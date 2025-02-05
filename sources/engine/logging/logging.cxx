#include <engine/logging/logging.hxx>
#include <engine/plugins/plugins.hxx>
#include <functional>
#include <memory>
#include <spdlog/async.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace engine::logging
{
    Logging &Logging::operator=(const Logging &p_log)
    {
        if (this != &p_log) {
            config = p_log.config;
            m_logger = p_log.m_logger;
        }
        return *this;
    }

    void Logging::bind_to_lua(sol::state_view &p_lua)
    {
        p_lua.new_usertype<logging::Logging>(
            "Logging",
            sol::constructors<logging::Logging()>(),
            "load",
            &Logging::load,
#ifdef ENGINE_PRO
            "register_plugins",
            &Logging::register_plugins,
#endif
            "config",
            &Logging::config);
    }

    void Logging::load()
    {
        const auto &logging_config = config.logging;
        active_instance(logging_config.type, logging_config.name);
    }

    void Logging::active_instance(const std::string &p_type,
                                  const std::string &p_name)
    {
        m_logger = create_logger(p_type, p_name);
    }

    std::shared_ptr<spdlog::logger> Logging::get_logger(
        const std::string &p_name)
    {
        return spdlog::get(p_name);
    }

    std::shared_ptr<spdlog::logger> Logging::create_logger(
        const std::string &p_type, const std::string &p_name)
    {
        std::vector<spdlog::sink_ptr> sinks;
        const auto &logging_config = config.logging;

        if (p_type == "daily") {
            sinks.emplace_back(
                std::make_shared<spdlog::sinks::daily_file_sink_mt>(
                    logging_config.filepath,
                    logging_config.daily_settings.hours,
                    logging_config.daily_settings.minutes,
                    false,
                    logging_config.daily_settings.max_size));
        } else if (p_type == "rotation") {
            sinks.emplace_back(
                std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    logging_config.filepath,
                    logging_config.rotation_settings.max_size,
                    logging_config.rotation_settings.max_files));
        } else {
            sinks.emplace_back(
                std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                    logging_config.filepath, true));
        }

        if (logging_config.console) {
            if (std::none_of(sinks.begin(), sinks.end(), [](const auto &sink) {
                    return dynamic_cast<spdlog::sinks::stdout_color_sink_mt *>(
                               sink.get()) != nullptr;
                })) {
                sinks.emplace_back(
                    std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
            }
        }

        auto logger = std::make_shared<spdlog::logger>(
            p_name, sinks.begin(), sinks.end());
        spdlog::register_logger(logger);

        logger->flush_on(static_cast<spdlog::level::level_enum>(
            logging_config.trace.interval));
        logger->set_pattern(logging_config.pattern);
        logger->set_level(
            static_cast<spdlog::level::level_enum>(logging_config.level));

        return logger;
    }

    void Logging::warn(const std::string &p_msg)
    {
        m_logger->warn(p_msg);
    }

    void Logging::info(const std::string &p_msg)
    {
        m_logger->info(p_msg);
    }

    void Logging::error(const std::string &p_msg)
    {
        m_logger->error(p_msg);
    }

    void Logging::debug(const std::string &p_msg)
    {
        m_logger->debug(p_msg);
    }

    void Logging::critical(const std::string &p_msg)
    {
        m_logger->critical(p_msg);
    }

#ifdef ENGINE_PRO
    void Logging::register_plugins()
    {
        plugins::Plugins::lua.state["logging"] = this;
        plugins::Plugins::lua.state.new_usertype<Logging>(
            "Logging",
            "info",
            static_cast<void (Logging::*)(const std::string &)>(&Logging::info),
            "warn",
            static_cast<void (Logging::*)(const std::string &)>(&Logging::warn),
            "critical",
            static_cast<void (Logging::*)(const std::string &)>(
                &Logging::critical),
            "debug",
            static_cast<void (Logging::*)(const std::string &)>(
                &Logging::debug),
            "error",
            static_cast<void (Logging::*)(const std::string &)>(
                &Logging::error));
    }
#endif

} // namespace engine::logging
