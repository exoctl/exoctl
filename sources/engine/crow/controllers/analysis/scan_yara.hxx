#pragma once

#include <engine/dto/dto.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/yara/yara.hxx>

#include <cstdint>
#include <string>

namespace Controllers
{
    namespace Analysis
    {
        class ScanYara : public DTO::DTOBase
        {
          public:
            ScanYara();
            ScanYara(Parser::Toml &);
            ~ScanYara();

            const void yara_scan_bytes(const std::string);
            const void yara_load_rules(
                const std::function<void(void *)> &) const;

          private:
            const std::string m_yara_rules;
            Parser::Toml &m_config;
            Security::Yara m_yara;
        };
    } // namespace Analysis
} //  namespace Controllers