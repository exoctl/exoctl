#pragma once

#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/yara.hxx>
#include <engine/server/focades/analysis/scan/yara/entitys.hxx>
#include <string>

namespace engine
{
    namespace focades
    {
        namespace analysis
        {
            namespace scan
            {
                class Yara
#ifdef ENGINE_PRO
                    : public interface::IPlugins
#endif
                {
                  public:
                    Yara();
                    Yara(configuration::Configuration &);
                    ~Yara() = default;
#ifdef ENGINE_PRO
                    void register_plugins() override;
#endif
                    void scan_fast_bytes(
                        const std::string,
                        const std::function<void(yara::record::DTO *)> &);
                    void load_rules(
                        const std::function<void(uint64_t)> &) const;

                    const engine::parser::Json dto_json(
                        const yara::record::DTO *);

                  private:
                    configuration::Configuration &m_config;
                    security::Yara m_yara;
                };
            } // namespace scan
        } // namespace analysis
    } // namespace focades
} // namespace engine