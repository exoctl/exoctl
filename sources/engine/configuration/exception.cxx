#include <engine/configuration/exception.hxx>

namespace engine
{
    namespace configuration
    {
        namespace exception
        {
            Load::Load(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *Load::what() const noexcept
            {
                return m_error_message.c_str();
            }

            Get::Get(const std::string &p_message) : m_error_message(p_message)
            {
            }
            const char *Get::what() const noexcept
            {
                return m_error_message.c_str();
            }
        } // namespace exception
    } // namespace configuration
} // namespace engine