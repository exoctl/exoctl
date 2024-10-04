#include <engine/exception.hxx>
#include <engine/magic/exception.hxx>
#include <string>

namespace magic
{
    namespace exception
    {
        Initialize::Initialize(const std::string &p_message)
            : ::exception::Exception(p_message)
        {
        }

        Finalize::Finalize(const std::string &p_message)
            : ::exception::Exception(p_message)
        {
        }
    } // namespace exception
} // namespace magic