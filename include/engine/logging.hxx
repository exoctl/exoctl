#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/parser/toml.hxx>
#include <spdlog/spdlog.h>
#include <stdint.h>

#define LOG(obj, type, msg, ...) obj.type(msg, ##__VA_ARGS__)

namespace logging
{
    class Logging
    {
      public:
        Logging(configuration::Configuration &);
        ~Logging();

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

      private:
        configuration::Configuration &m_config;
        std::shared_ptr<spdlog::logger> m_logger;

        void active_level(const uint16_t);
        void active_type(const std::string &);
        void active_trace(const uint16_t);
        void active_console(const bool);
    };
} // namespace logging