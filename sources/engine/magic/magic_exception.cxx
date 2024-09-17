#include <engine/exception.hxx>
#include <engine/magic/magic_exception.hxx>
#include <string>

namespace Magic
{
    namespace MagicException
    {

        Initialize::Initialize(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

        Finalize::Finalize(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

    } // namespace MagicException
} // namespace Magic
