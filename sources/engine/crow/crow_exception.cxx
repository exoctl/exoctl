#include <engine/crow/crow_exception.hxx>

namespace Crow
{
    namespace CrowException
    {
        Abort::Abort(const std::string &p_message) : ExceptionBase(p_message)
        {
        }
        ParcialAbort::ParcialAbort(const std::string &p_message)
            : ExceptionBase(p_message)
        {
        }

    } // namespace CrowException
} // namespace Crow
