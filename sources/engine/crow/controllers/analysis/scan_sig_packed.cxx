#include <engine/crow/controllers/analysis/scan_sig_packed.hxx>

namespace Controllers
{
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
} // namespace Controllers