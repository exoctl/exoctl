#include <engine/exception.hxx>

namespace Exception
{
BaseException::BaseException(const std::string &message)
    : m_error_message(message)
{
}

const char *BaseException::what() const noexcept
{
    return m_error_message.c_str();
}
} // namespace Exception