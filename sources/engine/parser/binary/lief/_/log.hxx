#pragma once

#include <LIEF/LIEF.hpp>
#include <LIEF/logging.h>
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
        configuration::Configuration &m_config;
        logging::Logging &m_log;

      protected:
        void active_level(const LIEF::logging::LEVEL);
    };
} // namespace engine::parser::binary::lief::_