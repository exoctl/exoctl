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
            config_ = p_log.config_;
            logger_ = p_log.logger_;
        }
        return *this;
    }

    void Logging::setup(const configuration::Configuration &p_config)
    {
        config_ = p_config;
    }

    void Logging::load()
    {
        active_instance(
            config_.get("logging.type").value<std::string>().value(),
            config_.get("logging.name").value<std::string>().value());
    }

    void Logging::active_instance(const std::string &p_type,
                                  const std::string &p_name)
    {
        logger_ = create_logger(p_type, p_name);
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

        if (p_type == "daily") {
            auto time = config_.get("logging.daily.time").as_time();
            sinks.emplace_back(std::make_shared<
                               spdlog::sinks::daily_file_sink_mt>(
                config_.get("logging.path").value<std::string>().value() +
                    config_.get("logging.file").value<std::string>().value(),
                time->get().hour,
                time->get().minute,
                config_.get("logging.daily.truncate").value<bool>().value(),
                config_.get("logging.daily.max_size")
                    .value<int64_t>()
                    .value()));
        } else if (p_type == "rotation") {
            sinks.emplace_back(
                std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    config_.get("logging.path").value<std::string>().value() +
                        config_.get("logging.file")
                            .value<std::string>()
                            .value(),
                    config_.get("logging.rotation.max_size")
                        .value<int64_t>()
                        .value(),
                    config_.get("logging.rotation.max_files")
                        .value<int64_t>()
                        .value()));
        } else {
            sinks.emplace_back(
                std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                    config_.get("logging.path").value<std::string>().value() +
                        config_.get("logging.file")
                            .value<std::string>()
                            .value(),
                    true));
        }

        if (config_.get("logging.console.output_enabled")
                .value<bool>()
                .value()) {
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
            config_.get("logging.trace_updates.interval")
                .value<int64_t>()
                .value()));
        logger->set_pattern(
            config_.get("logging.pattern").value<std::string>().value());
        logger->set_level(static_cast<spdlog::level::level_enum>(
            config_.get("logging.level").value<int64_t>().value()));

        return logger;
    }

    void Logging::warn(const std::string &p_msg)
    {
        logger_->warn(p_msg);
    }

    void Logging::info(const std::string &p_msg)
    {
        logger_->info(p_msg);
    }

    void Logging::error(const std::string &p_msg)
    {
        logger_->error(p_msg);
    }

    void Logging::debug(const std::string &p_msg)
    {
        logger_->debug(p_msg);
    }

    void Logging::critical(const std::string &p_msg)
    {
        logger_->critical(p_msg);
    }
} // namespace engine::logging