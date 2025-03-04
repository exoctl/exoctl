#include <engine/bridge/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/memory/memory.hxx>
#include <fmt/core.h>

namespace engine::bridge::focades::analysis::scan::av::clamav
{
    Clamav::Clamav() : m_clamav()
    {
    }

    void Clamav::setup(configuration::Configuration &p_config)
    {
        m_config = &p_config;
    }

    void Clamav::load_rules(const std::function<void(unsigned int)> &p_callback)
    {
        m_clamav.load_rules([&]() {
            m_clamav.set_db_rule_fd(
                m_config->get("av.clamav.database.default_path")
                    .value<std::string>()
                    .value(),
                CL_DB_STDOPT);
        });

        if (!IS_NULL(p_callback)) {
            p_callback(m_clamav.rules_loaded_count);
        }
    }

    void Clamav::scan_fast_bytes(
        const std::string &p_buffer,
        const std::function<void(clamav::record::DTO *)> &p_callback)
    {
        if (!IS_NULL(p_callback) && !p_buffer.empty()) {
            auto dto = std::make_unique<clamav::record::DTO>();

            security::av::clamav::record::scan::Options scanopts;
            scanopts.general = CL_SCAN_GENERAL_ALLMATCHES |
                               CL_SCAN_GENERAL_HEURISTICS |
                               CL_SCAN_GENERAL_COLLECT_METADATA;
            scanopts.parse = ~0;
            scanopts.heuristic = CL_SCAN_HEURISTIC_MACROS;
            scanopts.dev =
                CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO | CL_SCAN_DEV_COLLECT_SHA;

            m_clamav.scan_fast_bytes(
                p_buffer,
                scanopts,
                [&](const security::av::clamav::record::Data *p_data) {
                    dto->math_status = p_data->math_status;
                    dto->virname = p_data->virname;
                });

            p_callback(dto.get());
        }
    }

    const engine::parser::Json Clamav::dto_json(clamav::record::DTO *p_dto)
    {
        parser::Json json;

        if (!IS_NULL(p_dto)) {

            json.add("virname", p_dto->virname);
            json.add("math_status", (int) p_dto->math_status);
        }

        return json;
    }
} // namespace engine::bridge::focades::analysis::scan::av::clamav