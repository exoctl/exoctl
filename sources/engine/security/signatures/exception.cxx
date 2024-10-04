#include <engine/security/signatures/exception.hxx>

namespace security
{
    namespace sig
    {
        namespace exception
        {
            CompilerSig::CompilerSig(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

        } // namespace exception
    } // namespace sig
} // namespace security