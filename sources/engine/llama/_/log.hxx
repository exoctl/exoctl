#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/llama/llama.hxx>
#include <engine/logging.hxx>

namespace engine
{
    namespace llama
    {
        namespace _
        {
            class Log
            {
              public:
                Log(configuration::Configuration &, logging::Logging &);
                ~Log();

                static void log(ggml_log_level, const char *, void *);

              private:
                configuration::Configuration &m_config;
                logging::Logging &m_log;
            };
        } // namespace _
    } // namespace llama
} // namespace engine