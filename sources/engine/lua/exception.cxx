#include <engine/lua/exception.hxx>

namespace engine
{
    namespace lua
    {
        namespace exception
        {
            RegisterClassMember::RegisterClassMember(const std::string &p_message)
                : m_error_message(p_message)
            {
            }

            const char *RegisterClassMember::what() const noexcept
            {
                return m_error_message.c_str();
            }
        } // namespace exception
    } // namespace lua
} // namespace engine