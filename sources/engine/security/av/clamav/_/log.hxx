#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/clamav.hxx>

namespace engine::security::av::clamav::_
{
    class Log
    {
      public:
        Log() = default;
        ~Log() = default;

        static void log(enum cl_msg, const char *, const char *, void *);
        void setup(configuration::Configuration &, logging::Logging &);

      private:
        static configuration::Configuration config_;
        static logging::Logging log_;
    };
} // namespace engine::security::av::clamav::_