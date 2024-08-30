#include <engine/analysis/scan_sig_packed.hxx>

namespace Analysis
{
ScanPacked::ScanPacked() {}
ScanPacked::~ScanPacked() {}

const void ScanPacked::packed_scan_bytes(const std::string) {}
const void
ScanPacked::packed_load_rules(const std::function<void(void *)> &) const
{
}
} // namespace Analysis