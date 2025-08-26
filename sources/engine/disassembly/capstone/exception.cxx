#include <engine/disassembly/capstone/exception.hxx>

namespace engine
{
    namespace disassembly
    {
        namespace capstone
        {
            namespace exception
            {
                Initialize::Initialize(const std::string &p_message)
                    : error_message_(p_message)
                {
                }
                const char *Initialize::what() const noexcept
                {
                    return error_message_.c_str();
                }
            } // namespace exception
        } // namespace capstone
    } // namespace disassembly
} // namespace engine