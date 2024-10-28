#include <engine/server/exception.hxx>

namespace engine
{
    namespace server
    {
        namespace exception
        {
            Abort::Abort(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *Abort::what() const noexcept
            {
                return m_error_message.c_str();
            }

            ParcialAbort::ParcialAbort(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *ParcialAbort::what() const noexcept
            {
                return m_error_message.c_str();
            }

        } // namespace exception
    } // namespace server
} // namespace engine