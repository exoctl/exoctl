#pragma once

#include <cstdint>
#include <engine/crowapp/focades/analysis/scan/yara/entitys.hxx>
#include <engine/parser/json.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/yara/yara.hxx>
#include <string>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            class Yara
            {
              public:
                Yara();
                Yara(parser::Toml &);
                ~Yara();

                void yara_scan_fast_bytes(
                    const std::string,
                    const std::function<void(yara::record::DTO *)> &);
                void yara_load_rules(
                    const std::function<void(uint64_t)> &) const;

                const parser::Json yara_dto_json(const yara::record::DTO *);

              private:
                const std::string m_yara_malware_rules;
                const std::string m_yara_packeds_rules;
                const std::string m_yara_cve_rules;
                parser::Toml &m_config;
                security::Yara m_yara;
            };
        } // namespace scan
    } // namespace analysis
} // namespace focades
