#pragma once

#include <cstdint>
#include <engine/dto/dto.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/signatures/signatures.hxx>
#include <string>

namespace Controllers
{
    namespace Analysis
    {
        class ScanSig : public DTO::DTOBase
        {
          public:
            ScanSig();
            ~ScanSig();

            const void packed_scan_bytes(const std::string);
            const void packed_load_rules(
                const std::function<void(void *)> &) const;

          private:
        };
    } // namespace Analysis
} //  namespace Controllers