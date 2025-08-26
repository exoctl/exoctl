#pragma once

#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/logging/extend/logging.hxx>
#include <spdlog/spdlog.h>

namespace engine
{
    namespace logging
    {
        class Logging;

        class Logging
        {
          public:
            Logging() = default;
            ~Logging() = default;
            Logging &operator=(const Logging &);
            void setup(const configuration::Configuration &);
            void load();

            friend class extend::Logging;

            template <typename... Args>
            void warn(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                logger_->warn(p_msg, std::forward<Args>(p_args)...);
            }

            void warn(const std::string &);

            template <typename... Args>
            void info(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                logger_->info(p_msg, std::forward<Args>(p_args)...);
            }

            void info(const std::string &);

            template <typename... Args>
            void error(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                logger_->error(p_msg, std::forward<Args>(p_args)...);
            }

            void error(const std::string &);

            template <typename... Args>
            void debug(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                logger_->debug(p_msg, std::forward<Args>(p_args)...);
            }

            void debug(const std::string &);

            template <typename... Args>
            void critical(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                logger_->critical(p_msg, std::forward<Args>(p_args)...);
            }

            void critical(const std::string &);

            std::shared_ptr<spdlog::logger> create_logger(const std::string &,
                                                          const std::string &);

            static std::shared_ptr<spdlog::logger> get_logger(
                const std::string &);

          private:
            configuration::Configuration config_;
            std::shared_ptr<spdlog::logger> logger_;

          protected:
            void active_instance(const std::string &, const std::string &);
        };
    } // namespace logging
} // namespace engine