#include <engine/crow/controllers/analysis/scan_yara.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <iostream>
#include <string>

namespace Controllers
{
    namespace Analysis
    {
        ScanYara::~ScanYara()
        {
        }
        ScanYara::ScanYara(Parser::Toml &p_config)
            : m_yara_malware_rules(GET_TOML_TBL_VALUE(
                  p_config, string, "yara", "malware_rules")),
              m_yara_packeds_rules(GET_TOML_TBL_VALUE(
                  p_config, string, "yara", "packeds_rules")),
              m_config(p_config)
        {
            dto_set_field("yara_rule", "none");
            dto_set_field("yara_namespace", "none");
            dto_set_field("yara_match_status", Security::Types::Yara::yara_none);
        }

        const void ScanYara::yara_load_rules(
            const std::function<void(void *)> &p_callback) const
        {
            m_yara.yara_load_rules([&](void *p_rules_count) {
                m_yara.yara_load_rules_folder(
                    m_yara_packeds_rules); // rules for packeds
                m_yara.yara_load_rules_folder(
                    m_yara_malware_rules); // rules for malwares
                /* implement based demand */
            });

            p_callback((void *) m_yara.get_rules_loaded_count());
        }

        const void ScanYara::yara_scan_bytes(const std::string p_buffer)
        {
            m_yara.yara_scan_bytes(p_buffer, [&](void *yr_user_data) {
                dto_set_field(
                    "yara_match_status",
                    ((Security::yr_user_data *) yr_user_data)->yara_match_status);

                dto_set_field(
                    "yara_rule",
                    ((Security::yr_user_data *) yr_user_data)->yara_rule);
                dto_set_field(
                    "yara_namespace",
                    ((Security::yr_user_data *) yr_user_data)->yara_namespace);
            });
        }
    } // namespace Analysis
} //  namespace Controllers