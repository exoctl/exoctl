#pragma once

#include <crow.h>
#include <engine/configuration/configuration.hxx>
#include <engine/logging/logging.hxx>

namespace engine
{
    namespace server
    {
        namespace _
        {
            class Log : public crow::ILogHandler
            {
              public:
                Log() = default;
                ~Log() = default;

                void setup(configuration::Configuration &, logging::Logging &);
                void log(std::string, crow::LogLevel) override;

              private:
                configuration::Configuration m_config;
                logging::Logging m_log;

              protected:
                void active_level(crow::LogLevel);
            };
        } // namespace _
    } // namespace server
} // namespace engine