#include <engine/exception.hxx>

namespace exception
{
    Exception::Exception(const std::string &message) : m_error_message(message)
    {
    }

    const char *Exception::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace exception