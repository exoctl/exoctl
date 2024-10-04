#include <engine/security/clamav/clamav_exception.hxx>

namespace Security
{
    namespace ClamavException
    {

        Initialize::Initialize(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

        LoadRules::LoadRules(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

        SetDbRules::SetDbRules(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }
    } // namespace ClamavException
} // namespace Security