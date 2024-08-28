#pragma once

#include <cstdint>
#include <engine/dto.hxx>
#include <engine/parser/toml.hxx>
#include <string>

namespace Analysis
{
class ScanPacked : public DTOBase
{
  public:
    ScanPacked();
    ~ScanPacked();

    const void scan_packed_bytes(const std::string);
    const void load_packed_rules(const std::function<void(void *)> &) const;

  private:
};
}; // namespace Analysis