#include <engine/llama/exception.hxx>

namespace engine
{
    namespace llama
    {
        namespace exception
        {
            GenerateMessage::GenerateMessage(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *GenerateMessage::what() const noexcept
            {
                return m_error_message.c_str();
            }
        } // namespace exception
    } // namespace llama
} // namespace engine