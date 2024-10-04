#pragma once

#include <engine/crowapp/focades/analysis/scan/clamav/entitys.hxx>
#include <engine/parser/json.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/clamav/clamav.hxx>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            class Clamav
            {
              public:
                Clamav(parser::Toml &);
                ~Clamav();

                void clamav_scan_fast_bytes(
                    const std::string &,
                    const std::function<void(clamav::record::DTO *)> &);
                void clamav_load_rules(
                    const std::function<void(unsigned int)> & = nullptr);
                parser::Json clamav_dto_json(clamav::record::DTO *);

              private:
                security::Clamav m_clamav;
                parser::Toml &m_config;
                const std::string m_clamav_default_rules;
            };
        } // namespace scan
    } // namespace analysis
} // namespace focades