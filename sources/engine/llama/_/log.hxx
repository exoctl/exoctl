#pragma once

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
                configuration::Configuration config_;
                logging::Logging log_;
            };
        } // namespace _
    } // namespace llama
} // namespace engine