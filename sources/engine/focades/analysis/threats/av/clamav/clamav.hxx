#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/focades/analysis/threats/av/clamav/entitys.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/clamav.hxx>

namespace engine::focades::analysis::threats::av::clamav
{
    class Clamav
    {
      public:
        Clamav();
        void setup(configuration::Configuration &);
        ~Clamav() = default;

        void scan(const std::string &,
                  const std::function<void(clamav::record::DTO *)> &);
        void load(const std::function<void(unsigned int)> & = nullptr);
        const engine::parser::json::Json dto_json(clamav::record::DTO *);

        security::av::clamav::Clamav clamav;

      private:
        configuration::Configuration *config_;
    };
} // namespace engine::focades::analysis::threats::av::clamav