#include <engine/security/av/clamav/_/log.hxx>

namespace engine::security::av::clamav::_
{
    configuration::Configuration Log::config_;
    logging::Logging Log::log_;

    void Log::setup(configuration::Configuration &p_config,
                    logging::Logging &p_log)

    {
        config_ = p_config;
        log_ = p_log;

        log_.create_logger(
            config_.get("logging.type").value<std::string>().value(),
            config_.get("clamav._.log.name").value<std::string>().value());

        cl_set_clcb_msg(&Log::log);
    }

    void Log::log(enum cl_msg severity,
                  const char *p_fullmsg,
                  const char *p_msg,
                  void *p_ctx)
    {
        switch (severity) {
            case CL_MSG_ERROR:
                log_
                    .get_logger(config_.get("clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->error("{}", p_msg);
                break;
            case CL_MSG_WARN:
                log_
                    .get_logger(config_.get("clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->warn("{}", p_msg);
                break;
            case CL_MSG_INFO_VERBOSE:
                log_
                    .get_logger(config_.get("clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->debug("{}", p_msg);
                break;
            default:
                log_
                    .get_logger(config_.get("clamav._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->debug("{}", p_msg);
                break;
        }
    }
} // namespace engine::security::av::clamav::_
