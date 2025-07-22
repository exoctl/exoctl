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
        m_yara->set_rules_folder(
            m_config->get("bridge.focade.analysis.yara.rules.path")
                .value<std::string>()
                .value());

        m_yara->load_rules();
    }

    void Yara::scan(const std::string p_buffer,
                    const std::function<void(yara::record::DTO *)> &p_callback)
    {
        yara::record::DTO *dto = new yara::record::DTO;
        if (p_callback) {
            m_yara->scan_bytes(
                p_buffer,
                +[](YR_SCAN_CONTEXT *context,
                    int message,
                    void *message_data,
                    void *user_data) -> int {
                    if (user_data) {
                        yara::record::DTO *dto =
                            reinterpret_cast<yara::record::DTO *>(user_data);
                        const security::yara::type::Rule *rule =
                            reinterpret_cast<YR_RULE *>(message_data);

                        switch (message) {
                            case CALLBACK_MSG_SCAN_FINISHED:
                                break;

                            case CALLBACK_MSG_RULE_MATCHING:
                                dto->rules.push_back(*rule);
                                return CALLBACK_CONTINUE;

                            case CALLBACK_MSG_RULE_NOT_MATCHING:
                                break;
                        }

                        return CALLBACK_CONTINUE;
                    }
                    return 0;
                },
                (void *) dto,
                SCAN_FLAGS_FAST_MODE);

            p_callback(dto);
            delete dto;
        }
    }

    const engine::parser::Json Yara::dto_json(const yara::record::DTO *p_dto)
    {
        engine::parser::Json json;

        if (!IS_NULL(p_dto)) {
            engine::parser::Json rules_array;

            for (const auto &rule : p_dto->rules) {
                engine::parser::Json rule_json;
                rule_json.add("identifier", rule.identifier);
                rule_json.add("identifier", rule.flags);
                rules_array.add(rule_json);
            }

            json.add("rules", rules_array);
        }

        return json;
    }

} // namespace engine::bridge::focades::analysis::scan::yara
