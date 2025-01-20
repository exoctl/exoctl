#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/parser/toml.hxx>
#include <spdlog/spdlog.h>
#include <stdint.h>

#define LOG(obj, type, msg, ...) obj.type(msg, ##__VA_ARGS__)

namespace engine
{
    namespace logging
    {
        class Logging
        {
          public:
            Logging(configuration::Configuration &);
            ~Logging() = default;

            void load();

            template <typename... Args>
            void warn(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->warn(p_msg, std::forward<Args>(p_args)...);
            }

            template <typename... Args>
            void info(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->info(p_msg, std::forward<Args>(p_args)...);
            }

            template <typename... Args>
            void error(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->error(p_msg, std::forward<Args>(p_args)...);
            }

            template <typename... Args>
            void debug(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->debug(p_msg, std::forward<Args>(p_args)...);
            }

            template <typename... Args>
            void critical(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->critical(p_msg, std::forward<Args>(p_args)...);
            }

            std::shared_ptr<spdlog::logger> create_logger(const std::string &,
                                                          const std::string &);

            static std::shared_ptr<spdlog::logger> get_logger(
                const std::string &);

          private:
            configuration::Configuration &m_config;
            std::shared_ptr<spdlog::logger> m_logger;

          protected:
            void active_instance(const std::string &, const std::string &);
        };
    } // namespace logging
} // namespace engine