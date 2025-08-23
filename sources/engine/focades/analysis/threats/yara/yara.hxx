#pragma once

#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/focades/analysis/threats/yara/entitys.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/yara.hxx>
#include <string>

namespace engine::focades::analysis::threats::yara
{
    class Yara
    {
      public:
        Yara();
        ~Yara() = default;
        void setup(configuration::Configuration &);

        void scan(const std::string,
                  const std::function<void(yara::record::DTO *)> &);
        void load() const;

        const engine::parser::json::Json dto_json(const yara::record::DTO *);
        std::shared_ptr<security::Yara> yara;

        std::string rules_path;

      private:
        configuration::Configuration *m_config;
    };
} // namespace engine::focades::analysis::threats::yara