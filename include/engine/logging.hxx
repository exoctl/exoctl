#pragma once

#include <engine/parser/toml.hxx>
#include <spdlog/spdlog.h>
#include <stdint.h>

#define LOG(obj, type, msg, ...) obj.logging_##type(msg, ##__VA_ARGS__)

namespace logging
{
    class Logging
    {
      public:
        Logging(parser::Toml &);
        ~Logging();

        template <typename... Args>
        void logging_warn(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->warn(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void logging_info(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->info(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void logging_error(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->error(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void logging_debug(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->debug(p_msg, std::forward<Args>(p_args)...);
        }

        template <typename... Args>
        void logging_critical(fmt::format_string<Args...> p_msg, Args &&...p_args)
        {
            m_logger->critical(p_msg, std::forward<Args>(p_args)...);
        }

      private:
        parser::Toml &m_config;
        std::shared_ptr<spdlog::logger> m_logger;

        void logging_active_level(const uint16_t);
        void logging_active_type(const std::string &);
        void logging_active_trace(const uint16_t);
        void logging_active_console(const bool);
    };
} // namespace log