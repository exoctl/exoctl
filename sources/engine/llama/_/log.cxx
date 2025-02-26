#include <engine/llama/_/log.hxx>

namespace engine::llama::_
{
    void Log::setup(configuration::Configuration &p_config,
                    logging::Logging &p_log)

    {
        m_config = p_config;
        m_log = p_log;

        m_log.create_logger(
            m_config.get("logging.type").value<std::string>().value(),
            m_config.get("llama._.log.name").value<std::string>().value());

        llama_log_set(&Log::log, this);
    }

    void Log::log(ggml_log_level p_level,
                  const char *p_message,
                  void *p_user_data)
    {
        auto *logger_instance = reinterpret_cast<Log *>(p_user_data);
        if (logger_instance &&
            p_level >= logger_instance->m_config.get("llama._.log.level")
                           .value<int64_t>()
                           .value()) {
            switch (p_level) {
                case GGML_LOG_LEVEL_CONT:
                case GGML_LOG_LEVEL_NONE:
                    break;

                case GGML_LOG_LEVEL_DEBUG:
                    logger_instance->m_log
                        .get_logger(
                            logger_instance->m_config.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->debug("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_INFO:
                    logger_instance->m_log
                        .get_logger(
                            logger_instance->m_config.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->info("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_WARN:
                    logger_instance->m_log
                        .get_logger(
                            logger_instance->m_config.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->warn("{}", p_message);
                    break;
                case GGML_LOG_LEVEL_ERROR:
                    logger_instance->m_log
                        .get_logger(
                            logger_instance->m_config.get("llama._.log.name")
                                .value<std::string>()
                                .value())
                        ->error("{}", p_message);
                    break;
            }
        }
    }
} // namespace engine::llama::_
