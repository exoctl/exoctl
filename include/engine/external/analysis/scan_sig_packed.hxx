#pragma once

#include <cstdint>
#include <engine/dto/dto.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/signatures/signatures.hxx>
#include <string>

namespace Analysis
{
class ScanSigPacked : public DTO::DTOBase
{
  public:
    ScanSigPacked();
    ~ScanSigPacked();

    const void packed_scan_bytes(const std::string);
    const void packed_load_rules(const std::function<void(void *)> &) const;

  private:
};
}; // namespace Analysis