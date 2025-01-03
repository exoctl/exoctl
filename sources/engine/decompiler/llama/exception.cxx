#include <engine/decompiler/llama/exception.hxx>
#include <string>

namespace engine
{
    namespace decompiler
    {
        namespace llama
        {
            Initialize::Initialize(const std::string &p_message)
                : m_error_message(p_message)
            {
            }
            const char *Initialize::what() const noexcept
            {
                return m_error_message.c_str();
            }
        } // namespace llama
    } // namespace decompiler
} // namespace engine