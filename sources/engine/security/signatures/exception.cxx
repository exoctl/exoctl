#include <engine/security/signatures/exception.hxx>

namespace security
{
    namespace sig
    {
        namespace exception
        {
            CompilerSig::CompilerSig(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *CompilerSig::what() const noexcept
            {
                return m_error_message.c_str();
            }

        } // namespace exception
    } // namespace sig
} // namespace security