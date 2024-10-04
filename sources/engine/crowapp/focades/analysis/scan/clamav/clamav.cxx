#include <engine/crowapp/focades/analysis/scan/clamav/clamav.hxx>
#include <engine/memory.hxx>
#include <fmt/core.h>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            Clamav::Clamav(parser::Toml &p_config)
                : m_clamav(), m_config(p_config),
                  m_clamav_default_rules(GET_TOML_TBL_VALUE(
                      p_config, string, "clamav", "default_database"))
            {
            }

            Clamav::~Clamav()
            {
            }

            void Clamav::clamav_load_rules(
                const std::function<void(unsigned int)> &p_callback)
            {
                m_clamav.clamav_load_rules([&]() {
                    m_clamav.clamav_set_db_rule_fd(m_clamav_default_rules,
                                                   CL_DB_STDOPT);
                });

                if (!IS_NULL(p_callback)) {
                    p_callback(m_clamav.clamav_get_rules_loaded_count());
                }
            }

            void Clamav::clamav_scan_fast_bytes(
                const std::string &p_buffer,
                const std::function<void(clamav::record::DTO *)> &p_callback)
            {
                if (!IS_NULL(p_callback)) {
                    struct clamav::record::DTO *dto = new clamav::record::DTO;

                    security::clamav::record::scan::Options scanopts;

                    scanopts.clamav_general =
                        CL_SCAN_GENERAL_ALLMATCHES |
                        CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE |
                        CL_SCAN_GENERAL_COLLECT_METADATA;
                    scanopts.clamav_parse = ~(0);
                    scanopts.clamav_heuristic =
                        CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;

                    m_clamav.clamav_scan_fast_bytes(
                        p_buffer,
                        scanopts,
                        [&](const security::clamav::record::Data *p_data) {
                            dto->clamav_math_status =
                                p_data->clamav_math_status;
                            dto->clamav_virname = p_data->clamav_virname;
                        });

                    p_callback(dto);
                    delete dto;
                }
            }
            parser::Json Clamav::clamav_dto_json(clamav::record::DTO *p_dto)
            {
                parser::Json json;

                if (!IS_NULL(p_dto)) {

                    json.json_add_member_string("clamav_virname",
                                                p_dto->clamav_virname);
                    json.json_add_member_int("clamav_math_status",
                                             p_dto->clamav_math_status);
                }

                return json;
            }
        } // namespace scan
    } // namespace analysis
} // namespace focades