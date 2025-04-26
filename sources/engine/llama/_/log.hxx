#pragma once

#if !defined(__arm__) || !defined(__aarch64__) || !defined(_M_ARM) ||          \
    !defined(_M_ARM64)

#include <engine/configuration/configuration.hxx>
#include <engine/llama/llama.hxx>
#include <engine/logging/logging.hxx>

namespace engine
{
    namespace llama
    {
        namespace _
        {
            class Log
            {
              public:
                Log() = default;
                ~Log() = default;

                static void log(ggml_log_level, const char *, void *);
                void setup(configuration::Configuration &, logging::Logging &);

              private:
                configuration::Configuration m_config;
                logging::Logging m_log;
            };
        } // namespace _
    } // namespace llama
} // namespace engine

#endif