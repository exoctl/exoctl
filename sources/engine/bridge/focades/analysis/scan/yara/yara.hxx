#pragma once

#include <cstdint>
#include <engine/bridge/focades/analysis/scan/yara/entitys.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/yara.hxx>
#include <string>

namespace engine::bridge::focades::analysis::scan::yara
{
    class Yara
#ifdef ENGINE_PRO
        : public interface::ISubPlugins<Yara>
#endif
    {
      public:
        Yara();
        ~Yara() = default;
        void setup(configuration::Configuration &);

#ifdef ENGINE_PRO
        void _plugins() override;
#endif

        void scan_fast_bytes(const std::string,
                             const std::function<void(yara::record::DTO *)> &);
        void load_rules(const std::function<void(uint64_t)> &) const;

        const engine::parser::Json dto_json(const yara::record::DTO *);

      private:
        std::shared_ptr<security::Yara> m_yara;
        configuration::Configuration *m_config;
    };
} // namespace engine::bridge::focades::analysis::scan::yara