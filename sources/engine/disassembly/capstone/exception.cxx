#include <engine/disassembly/capstone/exception.hxx>

namespace disassembly
{
    namespace capstone
    {
        namespace exception
        {
            Initialize::Initialize(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }
        } // namespace exception
    } // namespace capstone
} // namespace disassembly