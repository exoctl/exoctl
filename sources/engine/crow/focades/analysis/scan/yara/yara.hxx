#pragma once

#include <cstdint>
#include <engine/crow/focades/analysis/scan/yara/yara_types.hxx>
#include <engine/parser/json.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/yara/yara.hxx>
#include <string>

namespace Focades
{
    namespace Analysis
    {
        namespace Scan
        {
            class Yara
            {
              public:
                Yara();
                Yara(Parser::Toml &);
                ~Yara();

                void scan_yara_fast_bytes(
                    const std::string,
                    const std::function<void(Structs::DTO *)> &);
                void scan_yara_load_rules(
                    const std::function<void(void *)> &) const;

                const Parser::Json scan_yara_dto_json(const Structs::DTO *);

              private:
                const std::string m_yara_malware_rules;
                const std::string m_yara_packeds_rules;
                const std::string m_yara_cve_rules;
                Parser::Toml &m_config;
                Security::Yara m_yara;
            };
        } // namespace Scan
    } // namespace Analysis
} // namespace Focades
