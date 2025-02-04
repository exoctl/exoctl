#pragma once

#include <LIEF/LIEF.hpp>
#include <LIEF/logging.hpp>
#include <engine/configuration/configuration.hxx>
#include <engine/logging/logging.hxx>

namespace engine::parser::binary::lief::_
{
    class Log : public ::LIEF::logging::ILogHandler
    {
      public:
        Log() = default;
        ~Log() = default;

        void setup(configuration::Configuration &, logging::Logging &);
        void log(std::string, ::LIEF::logging::LEVEL) override;

      private:
        configuration::Configuration m_config;
        logging::Logging m_log;

      protected:
        void active_level(::LIEF::logging::LEVEL);
    };
} // namespace engine::parser::binary::lief::_