#include <engine/analysis/scan_sig_packed.hxx>

namespace Analysis
{
ScanPacked::ScanPacked()
{
    dto_set_field("is_packed", 0);
    dto_set_field("packed", "none");
}
ScanPacked::~ScanPacked() {}

const void ScanPacked::packed_scan_bytes(const std::string) {}
const void
ScanPacked::packed_load_rules(const std::function<void(void *)> &) const
{
}
} // namespace Analysis