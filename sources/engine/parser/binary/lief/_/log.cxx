#include <engine/parser/binary/lief/_/log.hxx>

namespace engine::parser::binary::lief::_
{
    Log::Log(configuration::Configuration &p_config, logging::Logging &p_log)
        : m_config(p_config), m_log(p_log)
    {
        Log::active_level(
            static_cast<LIEF::logging::LEVEL>(m_config.get_lief().log.level));

        spdlog::details::registry::instance().drop("LIEF");
        LIEF::logging::set_logger(
            *m_log.create_logger(m_config.get_logging().type, "LIEF"));
    }

    void Log::active_level(LIEF::logging::LEVEL p_level)
    {
        LIEF::logging::set_level(p_level);
    }
} // namespace engine::parser::binary::lief::_