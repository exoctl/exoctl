#pragma once

#include <LIEF/logging.h>
#include <LIEF/LIEF.hpp>
#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>

namespace engine::parser::binary::lief::_
{
    class Log
    {
      public:
        Log(configuration::Configuration &, logging::Logging &);
        ~Log() = default;

      private:
        void log(LIEF::logging::LEVEL, const std::string &);
        void active_level(LIEF::logging::LEVEL);
        configuration::Configuration &m_config;
        logging::Logging &m_log;
    };
} // namespace engine::parser::binary::lief::_