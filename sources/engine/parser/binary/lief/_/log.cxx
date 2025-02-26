#include <engine/parser/binary/lief/_/log.hxx>

namespace engine::parser::binary::lief::_
{
    void Log::setup(configuration::Configuration &p_config,
                    logging::Logging &p_log)

    {
        m_config = p_config;
        m_log = p_log;

        LIEF::logging::logger::setHandler(
            this); // define global logger for LIEF

        m_log.create_logger(
            m_config.get("logging.type").value<std::string>().value(),
            m_config.get("lief._.log.name").value<std::string>().value());

        Log::active_level(static_cast<LIEF::logging::LEVEL>(
            m_config.get("lief._.log.level").value<int64_t>().value()));
    }

    void Log::log(std::string p_message, ::LIEF::logging::LEVEL p_level)
    {
        switch (p_level) {
            case LIEF::logging::LEVEL::Trace:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->trace("{}", p_message);
                break;
            case LIEF::logging::LEVEL::Debug:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->debug("{}", p_message);
                break;
            case LIEF::logging::LEVEL::Info:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->info("{}", p_message);
                break;
            case LIEF::logging::LEVEL::Warn:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->warn("{}", p_message);
                break;
            case LIEF::logging::LEVEL::Err:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->error("{}", p_message);
                break;
            case LIEF::logging::LEVEL::Critical:
                m_log
                    .get_logger(m_config.get("lief._.log.name")
                                    .value<std::string>()
                                    .value())
                    ->critical("{}", p_message);
                break;
        }
    }

    void Log::active_level(::LIEF::logging::LEVEL p_level)
    {
        LIEF::logging::logger::setLogLevel(p_level);
    }
} // namespace engine::parser::binary::lief::_