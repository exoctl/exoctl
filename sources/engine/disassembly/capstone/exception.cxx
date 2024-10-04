#include <engine/disassembly/capstone/exception.hxx>

namespace disassembly
{
    namespace capstone
    {
        namespace exception
        {
            Initialize::Initialize(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *Initialize::what() const noexcept
            {
                return m_error_message.c_str();
            }
        } // namespace exception
    } // namespace capstone
} // namespace disassembly