#pragma once

#include <cstdint>
#include <engine/dto.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/signatures/signatures.hxx>
#include <string>

namespace Analysis
{
class ScanPacked : public DTO::DTOBase
{
  public:
    ScanPacked();
    ~ScanPacked();

    const void packed_scan_bytes(const std::string);
    const void packed_load_rules(const std::function<void(void *)> &) const;

  private:
};
}; // namespace Analysis