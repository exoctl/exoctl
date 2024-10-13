#pragma once

#include <crow.h>
#include <engine/crowapp/crowapp.hxx>
#include <engine/logging.hxx>

namespace engine
{
    namespace crowapp
    {
        class Log : public crow::ILogHandler
        {
          public:
            Log(CrowApp &);
            ~Log();

            void log(std::string, crow::LogLevel) override;
            void active_level(crow::LogLevel); // TODO: insert level in CrowLog
                                               // for remove message "Call
                                               // `app.loglevel(crow::LogLevel::Warning)`
                                               // to hide Info level logs."

          private:
            CrowApp &m_crowapp;
        };
    } // namespace crowapp
} // namespace engine