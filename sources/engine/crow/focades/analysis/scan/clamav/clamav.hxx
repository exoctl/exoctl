#pragma once

#include <engine/crow/focades/analysis/scan/clamav/clamav_types.hxx>
#include <engine/parser/json.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/clamav/clamav.hxx>

namespace Focades
{
    namespace Analysis
    {
        namespace Scan
        {
            class Clamav
            {
              public:
                Clamav(Parser::Toml &);
                ~Clamav();

                void clamav_scan_fast_bytes(
                    const std::string &,
                    const std::function<void(Cl::Structs::DTO *)> &);
                void clamav_load_rules(const std::function<void(unsigned int)> & = nullptr);
                Parser::Json clamav_dto_json(Cl::Structs::DTO *);

              private:
                Security::Clamav m_clamav;
                Parser::Toml &m_config;
                const std::string m_clamav_default_rules;
            };
        } // namespace Scan
    } // namespace Analysis
} // namespace Focades