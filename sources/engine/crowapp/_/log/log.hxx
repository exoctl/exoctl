#pragma once

#include <crow.h>
#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>

namespace engine
{
    namespace crowapp
    {
        namespace _
        {
            class Log : public crow::ILogHandler
            {
              public:
                Log(configuration::Configuration &, logging::Logging &);
                ~Log();

                void log(std::string, crow::LogLevel) override;

              private:
                void active_level(crow::LogLevel);
                configuration::Configuration &m_config;
                logging::Logging &m_log;
            };
        } // namespace _
    } // namespace crowapp
} // namespace engine