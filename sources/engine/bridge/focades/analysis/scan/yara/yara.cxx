#include <engine/bridge/focades/analysis/scan/yara/yara.hxx>
#include <engine/memory/memory.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/yara/exception.hxx>
#include <string>

namespace engine::bridge::focades::analysis::scan::yara
{
    Yara::Yara() : m_yara(std::make_shared<security::Yara>())
    {
    }

    void Yara::setup(configuration::Configuration &p_config)
    {
        m_config = &p_config;
    }

    void Yara::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<yara::Yara>(
            "AnalysisYara", "yara", &Yara::m_yara);
    }

    void Yara::load_rules() const
    {
        m_yara->load_rules([&]() {
            m_yara->load_rules_folder(
                m_config->get("bridge.focade.analysis.yara.rules.path")
                    .value<std::string>()
                    .value());
        });
    }

    void Yara::scan(const std::string p_buffer,
                    const std::function<void(yara::record::DTO *)> &p_callback)
    {
        if (!IS_NULL(p_callback)) {
            // m_yara->scan_bytes(
            //     p_buffer, [&](security::yara::record::Data *p_data) {
            //         if (!IS_NULL(p_data)) {
            //             struct yara::record::DTO *dto = new
            //             yara::record::DTO;

            //            dto->match_status = p_data->match_status;
            //            dto->rule.assign(p_data->rule);
            //            dto->ns.assign(p_data->ns);

            //            p_callback(dto);
            //            delete dto;
            //        }
            //    });
        }
    }

    //const engine::parser::Json Yara::dto_json(const yara::record::DTO *p_dto)
    //{
    //    engine::parser::Json json;
//
    //    if (!IS_NULL(p_dto)) {
//
    //        json.add("ns", p_dto->ns);
    //        json.add("rule", p_dto->rule);
    //        json.add("match_status", (int) p_dto->match_status);
    //    }
//
    //    return json;
    //}
} // namespace engine::bridge::focades::analysis::scan::yara
