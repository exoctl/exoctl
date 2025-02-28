#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/clamav.hxx>
#include <engine/bridge/focades/analysis/scan/av/clamav/entitys.hxx>

namespace engine::focades::analysis::scan::av
{
    class Clamav
    {
      public:
        Clamav(configuration::Configuration &);
        ~Clamav() = default;

        void scan_fast_bytes(
            const std::string &,
            const std::function<void(clamav::record::DTO *)> &);
        void load_rules(const std::function<void(unsigned int)> & = nullptr);
        const engine::parser::Json dto_json(clamav::record::DTO *);

      private:
        security::av::Clamav m_clamav;
        configuration::Configuration &m_config;
    };
} // namespace engine::focades::analysis::scan::av