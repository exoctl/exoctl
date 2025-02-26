#include <engine/security/av/clamav/_/log.hxx>

namespace engine::security::av::clamav::_
{
    configuration::Configuration Log::m_config;
    logging::Logging Log::m_log;

    void Log::setup(configuration::Configuration &p_config,
                    logging::Logging &p_log)

    {
        m_config = p_config;
        m_log = p_log;

        m_log.create_logger(
            m_config.get("logging.type").value<std::string>().value(),
            m_config.get("av.clamav._.log.name").value<std::string>().value());

        cl_set_clcb_msg(&Log::log);
    }

    void Log::log(enum cl_msg severity,
                  const char *p_fullmsg,
                  const char *p_msg,
                  void *p_ctx)
    {
        switch (severity) {
            case CL_MSG_ERROR:
                m_log
                    .get_logger(m_config.get("av.clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->error("{}", p_msg);
                break;
            case CL_MSG_WARN:
                m_log
                    .get_logger(m_config.get("av.clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->warn("{}", p_msg);
                break;
            case CL_MSG_INFO_VERBOSE:
                m_log
                    .get_logger(m_config.get("av.clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->debug("{}", p_msg);
                break;
            default:
                m_log
                    .get_logger(m_config.get("av.clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->debug("{}", p_msg);
                break;
        }
    }
} // namespace engine::security::av::clamav::_
