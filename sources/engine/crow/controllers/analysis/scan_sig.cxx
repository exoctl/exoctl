#include <engine/crow/controllers/analysis/scan_sig.hxx>

namespace Controllers
{
    namespace Analysis
    {
        ScanSig::ScanSig()
        {
            dto_set_field("is_packed", 0);
            dto_set_field("packed", "none");
        }
        ScanSig::~ScanSig()
        {
        }

        const void ScanSig::packed_scan_bytes(const std::string)
        {
        }
        const void ScanSig::packed_load_rules(
            const std::function<void(void *)> &) const
        {
        }
    } // namespace Analysis
} //  namespace Controllers