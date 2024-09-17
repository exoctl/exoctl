#pragma once

#include <crow.h>
#include <engine/crow/crow.hxx>
#include <engine/log.hxx>

namespace Crow
{
    class Log : public crow::ILogHandler
    {
      public:
        Log(CrowApp &);
        ~Log();

        void log(std::string, crow::LogLevel) override;
        void log_active_level(
            crow::LogLevel); // TODO: insert level in CrowLog for remove message
                             // "Call `app.loglevel(crow::LogLevel::Warning)` to
                             // hide Info level logs."

      private:
        Logging::Log &m_log;
        CrowApp &m_crow;
    };
} // namespace Crow