#include <engine/crow/focades/analysis/scan_yara/scan_yara.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <string>

namespace Focades
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
              m_yara_cve_rules(
                  GET_TOML_TBL_VALUE(p_config, string, "yara", "cve_rules")),
              m_config(p_config)
        {
        }

        void ScanYara::scan_yara_load_rules(
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

        void ScanYara::scan_yara_fast_bytes(
            const std::string p_buffer,
            const std::function<void(Structs::DTO *)> &p_callback)
        {
            m_yara.yara_scan_fast_bytes(
                p_buffer, [&](Security::Structs::Data *p_data) {
                    struct Structs::DTO *dto = new  Structs::DTO;

                    dto->yara_match_status = p_data->yara_match_status;
                    dto->yara_rule.assign(p_data->yara_rule);
                    dto->yara_namespace.assign(p_data->yara_namespace);

                    p_callback(dto);
                    delete dto;
                });
        }
    } // namespace Analysis
} // namespace Focades
