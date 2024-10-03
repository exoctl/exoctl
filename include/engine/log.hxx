#pragma once

#include <engine/parser/toml.hxx>
#include <spdlog/spdlog.h>
#include <stdint.h>

#define LOG(obj, type, msg, ...) obj.log_##type(msg, ##__VA_ARGS__)

namespace Logging
{
    class Log
    {
      public:
        Log(Parser::Toml &);
        ~Log();

        template <typename... Args>
        void log_warn(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->warn(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void log_info(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->info(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void log_error(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->error(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void log_debug(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->debug(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void log_critical(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->critical(p_msg, std::forward<Args>(p_args)...);
        }

      private:
        Parser::Toml &m_config;
        std::shared_ptr<spdlog::logger> m_logger;

        void log_active_level(const uint16_t);
        void log_active_type(const std::string &);
        void log_active_trace(const uint16_t);
        void log_active_console(const bool);
    };
} // namespace Logging