#include <engine/llama/_/log.hxx>

namespace engine::llama::_
{
    void Log::setup(configuration::Configuration &p_config,
                    logging::Logging &p_log)

    {
        config_ = p_config;
        log_ = p_log;

        log_.create_logger(
            config_.get("logging.type").value<std::string>().value(),
            config_.get("llama._.log.name").value<std::string>().value());

        llama_log_set(&Log::log, this);
    }

    void Log::log(ggml_log_level p_level,
                  const char *p_message,
                  void *p_user_data)
    {
        auto *logger_instance = reinterpret_cast<Log *>(p_user_data);
        if (logger_instance &&
            p_level >= logger_instance->config_.get("llama._.log.level")
                           .value<int64_t>()
                           .value()) {
            switch (p_level) {
                case GGML_LOG_LEVEL_CONT:
                case GGML_LOG_LEVEL_NONE:
                    break;

                case GGML_LOG_LEVEL_DEBUG:
                    logger_instance->log_
                        .get_logger(
                            logger_instance->config_.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->debug("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_INFO:
                    logger_instance->log_
                        .get_logger(
                            logger_instance->config_.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->info("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_WARN:
                    logger_instance->log_
                        .get_logger(
                            logger_instance->config_.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->warn("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_ERROR:
                    logger_instance->log_
                        .get_logger(
                            logger_instance->config_.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->error("{}", p_message);
                    break;
            }
        }
    }
} // namespace engine::llama::_