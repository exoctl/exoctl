#include <engine/focades/analysis/threats/av/clamav/clamav.hxx>
#include <engine/memory/memory.hxx>
#include <fmt/core.h>

namespace engine::focades::analysis::threats::av::clamav
{
    Clamav::Clamav() : clamav()
    {
    }

    void Clamav::setup(configuration::Configuration &p_config)
    {
        config_ = &p_config;
    }

    void Clamav::load(const std::function<void(unsigned int)> &p_callback)
    {
        clamav.set_db_rule_fd(config_
                                  ->get("focades.analysis.av."
                                        "clamav.database.path")
                                  .value<std::string>()
                                  .value(),
                              CL_DB_STDOPT | CL_DB_PHISHING |
                                  CL_DB_PHISHING_URLS | CL_DB_PUA |
                                  CL_DB_OFFICIAL_ONLY | CL_DB_BYTECODE);
        clamav.load_rules();

        if (!IS_NULL(p_callback)) {
            p_callback(clamav.rules_loaded_count);
        }
    }

    void Clamav::scan(
        const std::string &p_buffer,
        const std::function<void(clamav::record::DTO *)> &p_callback)
    {
        if (!IS_NULL(p_callback) && !p_buffer.empty()) {
            auto dto = std::make_unique<clamav::record::DTO>();

            security::av::clamav::record::scan::Options scanopts;
            memset(&scanopts,
                   0,
                   sizeof(security::av::clamav::record::scan::Options));
            scanopts.general = CL_SCAN_GENERAL_ALLMATCHES |
                               CL_SCAN_GENERAL_HEURISTICS |
                               CL_SCAN_GENERAL_COLLECT_METADATA;
            scanopts.parse = ~0;
            scanopts.heuristic = CL_SCAN_HEURISTIC_MACROS;
            scanopts.dev =
                CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO | CL_SCAN_DEV_COLLECT_SHA;

            clamav.scan_bytes(
                p_buffer,
                scanopts,
                [&](const security::av::clamav::record::Data *p_data) {
                    dto->math_status = p_data->math_status;
                    dto->virname = p_data->virname;
                });

            p_callback(dto.get());
        }
    }

    const engine::parser::json::Json Clamav::dto_json(
        clamav::record::DTO *p_dto)
    {
        parser::json::Json json;

        if (!IS_NULL(p_dto)) {

            json.add("virname", p_dto->virname);
            json.add("math_status", (int) p_dto->math_status);
        }

        return json;
    }
} // namespace engine::focades::analysis::threats::av::clamav