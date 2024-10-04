#include <engine/crowapp/exception.hxx>

namespace crowapp
{
    namespace exception
    {
        Abort::Abort(const std::string &p_message)
            : ::exception::Exception(p_message)
        {
        }
        ParcialAbort::ParcialAbort(const std::string &p_message)
            : ::exception::Exception(p_message)
        {
        }

    } // namespace exception
} // namespace crowapp
