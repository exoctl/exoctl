#pragma once

#include <crow.h>
#include <engine/log.hxx>

namespace Crow
{
class CrowLog : public crow::ILogHandler
{
  public:
    CrowLog(Logging::Log &);
    ~CrowLog();

    void log(std::string, crow::LogLevel) override;

  private:
    Logging::Log &m_log;
};
} // namespace Crow