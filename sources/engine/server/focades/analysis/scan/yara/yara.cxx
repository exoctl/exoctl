#include <engine/memory/memory.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/focades/analysis/scan/yara/yara.hxx>
#include <string>

namespace engine
{
    namespace focades
    {
        namespace analysis
        {
            namespace scan
            {
                Yara::~Yara()
                {
                }
                Yara::Yara(configuration::Configuration &p_config)
                    : m_config(p_config)
                {
                }

                void Yara::load_rules(
                    const std::function<void(uint64_t)> &p_callback) const
                {
                    m_yara.load_rules([&]() {
                        m_yara.load_rules_folder(
                            m_config.get_yara()
                                .rules.cve_path); // rules for cve
                        m_yara.load_rules_folder(
                            m_config.get_yara()
                                .rules.malware_path); // rules for malwares
                        m_yara.load_rules_folder(
                            m_config.get_yara()
                                .rules.packed_path); // rules for packeds
                        /* implement based demand */
                    });

                    if (!IS_NULL(p_callback)) {
                        p_callback(m_yara.get_rules_loaded_count());
                    }
                }

                void Yara::scan_fast_bytes(
                    const std::string p_buffer,
                    const std::function<void(yara::record::DTO *)> &p_callback)
                {
                    if (!IS_NULL(p_callback)) {
                        m_yara.scan_fast_bytes(
                            p_buffer,
                            [&](security::yara::record::Data *p_data) {
                                if (!IS_NULL(p_data)) {
                                    struct yara::record::DTO *dto =
                                        new yara::record::DTO;

                                    dto->match_status = p_data->match_status;
                                    dto->rule.assign(p_data->rule);
                                    dto->ns.assign(p_data->ns);

                                    p_callback(dto);
                                    delete dto;
                                }
                            });
                    }
                }

                const engine::parser::Json Yara::dto_json(
                    const yara::record::DTO *p_dto)
                {
                    engine::parser::Json json;

                    if (!IS_NULL(p_dto)) {

                        json.add_member_string("ns", p_dto->ns);
                        json.add_member_string("rule", p_dto->rule);
                        json.add_member_int("match_status",
                                            p_dto->match_status);
                    }

                    return json;
                }
            } // namespace scan
        } // namespace analysis
    } // namespace focades
} // namespace engine