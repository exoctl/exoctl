#include <engine/exception.hxx>

namespace Exception
{
    ExceptionBase::ExceptionBase(const std::string &message)
        : m_error_message(message)
    {
    }

    const char *ExceptionBase::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace Exception