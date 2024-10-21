#pragma once

#include <LIEF/LIEF.hpp>
#include <LIEF/logging.hpp>
#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>

namespace engine::parser::binary::lief::_
{
    class Log : public LIEF::logging::ILogHandler
    {
      public:
        Log(configuration::Configuration &, logging::Logging &);
        ~Log();

        void log(std::string, LIEF::logging::LEVEL) override;

      private:
        configuration::Configuration &m_config;
        logging::Logging &m_log;

      protected:
        void active_level(LIEF::logging::LEVEL);
    };
} // namespace engine::parser::binary::lief::_