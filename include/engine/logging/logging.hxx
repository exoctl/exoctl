#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <spdlog/spdlog.h>
#include <stdint.h>

#define LOG(obj, type, msg, ...) obj.type(msg, ##__VA_ARGS__)

namespace engine
{
    namespace logging
    {
        class Logging : public interface::IBind
#ifdef ENGINE_PRO
            ,
                        public interface::IPlugins
#endif
        {
          public:
            Logging() = default;
            ~Logging() = default;
            Logging &operator=(const Logging &);
            void bind_to_lua(sol::state_view &) override;
            configuration::Configuration config;

#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
            void load();

            template <typename... Args>
            void warn(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->warn(p_msg, std::forward<Args>(p_args)...);
            }

            void warn(const std::string &p_msg);

            template <typename... Args>
            void info(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->info(p_msg, std::forward<Args>(p_args)...);
            }

            void info(const std::string &p_msg);

            template <typename... Args>
            void error(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->error(p_msg, std::forward<Args>(p_args)...);
            }

            void error(const std::string &p_msg);

            template <typename... Args>
            void debug(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->debug(p_msg, std::forward<Args>(p_args)...);
            }

            void debug(const std::string &p_msg);

            template <typename... Args>
            void critical(fmt::format_string<Args...> p_msg, Args &&...p_args)
            {
                m_logger->critical(p_msg, std::forward<Args>(p_args)...);
            }

            void critical(const std::string &p_msg);

            std::shared_ptr<spdlog::logger> create_logger(const std::string &,
                                                          const std::string &);

            static std::shared_ptr<spdlog::logger> get_logger(
                const std::string &);

          private:
            std::shared_ptr<spdlog::logger> m_logger;

          protected:
            void active_instance(const std::string &, const std::string &);
        };
    } // namespace logging
} // namespace engine