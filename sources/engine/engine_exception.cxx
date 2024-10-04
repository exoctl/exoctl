#include <engine/engine_exception.hxx>

namespace engine
{
    namespace exception
    {
        Run::Run(const std::string &p_message)
            : ::exception::Exception(p_message)
        {
        }
    } // namespace exception
} // namespace engine
