#include <engine/llama/exception.hxx>

namespace engine
{
    namespace llama
    {
        namespace exception
        {
            GenerateMessage::GenerateMessage(const std::string &p_message)
                : error_message_(p_message)
            {
            }
            const char *GenerateMessage::what() const noexcept
            {
                return error_message_.c_str();
            }
        } // namespace exception
    } // namespace llama
} // namespace engine