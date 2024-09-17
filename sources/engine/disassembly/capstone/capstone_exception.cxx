#include <engine/disassembly/capstone/capstone_exception.hxx>

namespace Disassembly
{
    namespace CapstoneException
    {
        Initialize::Initialize(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

        Finalize::Finalize(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

        FailedDisassembly::FailedDisassembly(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }
    } // namespace CapstoneException
} // namespace Disassembly