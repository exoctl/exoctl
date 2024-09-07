#include <engine/external/analysis/scan_sig_packed.hxx>

namespace Analysis
{
ScanSigPacked::ScanSigPacked()
{
    dto_set_field("is_packed", 0);
    dto_set_field("packed", "none");
}
ScanSigPacked::~ScanSigPacked() {}

const void ScanSigPacked::packed_scan_bytes(const std::string) {}
const void
ScanSigPacked::packed_load_rules(const std::function<void(void *)> &) const
{
}
} // namespace Analysis