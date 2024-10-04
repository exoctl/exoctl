#include <engine/magic/exception.hxx>
#include <string>

namespace magic
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

        Finalize::Finalize(const std::string &p_message)
            : m_error_message(p_message)
        {
        }
        const char *Finalize::what() const noexcept
        {
            return m_error_message.c_str();
        }
    } // namespace exception
} // namespace magic