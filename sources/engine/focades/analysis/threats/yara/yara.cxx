#include <engine/focades/analysis/threats/yara/yara.hxx>
#include <engine/memory/memory.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/yara/exception.hxx>
#include <string>

namespace engine::focades::analysis::threats::yara
{
    Yara::Yara() : yara(std::make_shared<security::Yara>())
    {
    }

    void Yara::setup(configuration::Configuration &p_config)
    {
        config_ = &p_config;

        rules_path.assign(config_->get("focades.analysis.yara.rules.path")
                              .value<std::string>()
                              .value());
    }

    void Yara::load() const
    {
        yara->set_rules_folder(rules_path);
        yara->load_rules();
    }

    void Yara::scan(const std::string p_buffer,
                    const std::function<void(yara::record::DTO *)> &p_callback)
    {
        yara::record::DTO *dto = new yara::record::DTO;
        dto->math_status = yara::type::Scan::nomatch;
        if (p_callback) {
            yara->scan_bytes(
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
                            case security::yara::type::Flags::ScanFinished:
                                break;

                            case security::yara::type::Flags::RuleMatching:
                                dto->math_status = yara::type::Scan::match;
                                dto->rules.push_back(*rule);
                                return CALLBACK_CONTINUE;

                            case security::yara::type::Flags::RuleNotMatching:
                                break;
                        }

                        return security::yara::type::Flags::ContinueScan;
                    }
                    return 0;
                },
                (void *) dto,
                security::yara::type::Flags::FastMode);

            p_callback(dto);
            delete dto;
        }
    }

    const engine::parser::json::Json Yara::dto_json(
        const yara::record::DTO *p_dto)
    {
        engine::parser::json::Json json;

        if (!IS_NULL(p_dto)) {
            engine::parser::json::Json rules_array;

            for (const auto &rule : p_dto->rules) {
                engine::parser::json::Json rule_json;
                rule_json.add("identifier", rule.identifier);
                rule_json.add("namespace", rule.ns->name);
                rules_array.add(rule_json);
            }

            json.add("rules", rules_array);
        }

        return json;
    }

} // namespace engine::focades::analysis::threats::yara
