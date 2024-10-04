#include <engine/crowapp/focades/analysis/scan/yara/yara.hxx>
#include <engine/memory.hxx>
#include <engine/security/yara/exception.hxx>
#include <string>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            Yara::~Yara()
            {
            }
            Yara::Yara(parser::Toml &p_config)
                : m_yara_malware_rules(GET_TOML_TBL_VALUE(
                      p_config, string, "yara", "malware_rules")),
                  m_yara_packeds_rules(GET_TOML_TBL_VALUE(
                      p_config, string, "yara", "packeds_rules")),
                  m_yara_cve_rules(GET_TOML_TBL_VALUE(
                      p_config, string, "yara", "cve_rules")),
                  m_config(p_config)
            {
            }

            void Yara::yara_load_rules(
                const std::function<void(uint64_t)> &p_callback) const
            {
                m_yara.yara_load_rules([&]() {
                    m_yara.yara_load_rules_folder(
                        m_yara_packeds_rules); // rules for packeds
                    m_yara.yara_load_rules_folder(
                        m_yara_malware_rules); // rules for malwares
                    /* implement based demand */
                });

                if (!IS_NULL(p_callback)) {
                    p_callback(m_yara.yara_get_rules_loaded_count());
                }
            }

            void Yara::yara_scan_fast_bytes(
                const std::string p_buffer,
                const std::function<void(yara::record::DTO *)> &p_callback)
            {
                if (!IS_NULL(p_callback)) {
                    m_yara.yara_scan_fast_bytes(
                        p_buffer, [&](security::yara::record::Data *p_data) {
                            if (!IS_NULL(p_data)) {
                                struct yara::record::DTO *dto = new yara::record::DTO;

                                dto->yara_match_status =
                                    p_data->yara_match_status;
                                dto->yara_rule.assign(p_data->yara_rule);
                                dto->yara_namespace.assign(
                                    p_data->yara_namespace);

                                p_callback(dto);
                                delete dto;
                            }
                        });
                }
            }

            const parser::Json Yara::yara_dto_json(
                const yara::record::DTO *p_dto)
            {
                parser::Json json;

                if (!IS_NULL(p_dto)) {

                    json.json_add_member_string("yara_namespace",
                                                p_dto->yara_namespace);
                    json.json_add_member_string("yara_rule", p_dto->yara_rule);
                    json.json_add_member_int("yara_match_status",
                                             p_dto->yara_match_status);
                }

                return json;
            }
        } // namespace scan
    } // namespace analysis
} // namespace focades
