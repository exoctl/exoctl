#include <engine/security/clamav/exception.hxx>

namespace security
{
    namespace clamav
    {
        namespace exception
        {
            Initialize::Initialize(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            LoadRules::LoadRules(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            SetDbRules::SetDbRules(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }
        } // namespace exception
    } // namespace clamav
} // namespace security