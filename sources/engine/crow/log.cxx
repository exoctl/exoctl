#include <engine/crow/log.hxx>

namespace Crow
{

CrowLog::CrowLog(Logging::Log &p_log) : m_log(p_log) {}

CrowLog::~CrowLog() {}

void CrowLog::log(std::string p_message, crow::LogLevel p_level)
{
    switch (p_level)
    {
    case crow::LogLevel::Debug:
        LOG(m_log, debug, "{}", p_message);
        break;
    case crow::LogLevel::Info:
        LOG(m_log, info, "{}", p_message);
        break;
    case crow::LogLevel::Warning:
        LOG(m_log, warn, "{}", p_message);
        break;
    case crow::LogLevel::Error:
        LOG(m_log, error, "{}", p_message);
        break;
    case crow::LogLevel::Critical:
        LOG(m_log, critical, "{}", p_message);
        break;
    }
}
} // namespace Crow