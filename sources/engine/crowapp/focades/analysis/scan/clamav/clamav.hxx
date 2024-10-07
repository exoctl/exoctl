#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/crowapp/focades/analysis/scan/clamav/entitys.hxx>
#include <engine/parser/json.hxx>
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
                Clamav(configuration::Configuration &);
                ~Clamav();

                void scan_fast_bytes(
                    const std::string &,
                    const std::function<void(clamav::record::DTO *)> &);
                void load_rules(
                    const std::function<void(unsigned int)> & = nullptr);
                parser::Json dto_json(clamav::record::DTO *);

              private:
                security::Clamav m_clamav;
                configuration::Configuration &m_config;
            };
        } // namespace scan
    } // namespace analysis
} // namespace focades