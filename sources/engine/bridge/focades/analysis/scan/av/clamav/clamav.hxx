#pragma once

#include <engine/bridge/focades/analysis/scan/av/clamav/entitys.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/clamav.hxx>

namespace engine::bridge::focades::analysis::scan::av::clamav
{
    class Clamav
    {
      public:
        Clamav();
        void setup(configuration::Configuration &);
        ~Clamav() = default;

        void scan(const std::string &,
                  const std::function<void(clamav::record::DTO *)> &);
        void load_rules(const std::function<void(unsigned int)> & = nullptr);
        const engine::parser::Json dto_json(clamav::record::DTO *);

      private:
        security::av::Clamav m_clamav;
        configuration::Configuration *m_config;
    };
} // namespace engine::bridge::focades::analysis::scan::av::clamav