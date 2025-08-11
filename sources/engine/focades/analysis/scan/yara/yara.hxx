#pragma once

#include <cstdint>
#include <engine/focades/analysis/scan/yara/entitys.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/yara.hxx>
#include <string>

namespace engine::focades::analysis::scan::yara
{
    class Yara : public interface::IPlugins<Yara>

    {
      public:
        Yara();
        ~Yara() = default;
        void setup(configuration::Configuration &);

        void _plugins() override;
        void scan(const std::string,
                  const std::function<void(yara::record::DTO *)> &);
        void load() const;

        const engine::parser::Json dto_json(const yara::record::DTO *);

      private:
        std::shared_ptr<security::Yara> m_yara;
        configuration::Configuration *m_config;
    };
} // namespace engine::focades::analysis::scan::yara