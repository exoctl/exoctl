#include <engine/magic/exception.hxx>
#include <string>

namespace engine
{
    namespace magic
    {
        namespace exception
        {
            Initialize::Initialize(const std::string &p_message)
                : error_message_(p_message)
            {
            }
            const char *Initialize::what() const noexcept
            {
                return error_message_.c_str();
            }

            Finalize::Finalize(const std::string &p_message)
                : error_message_(p_message)
            {
            }
            const char *Finalize::what() const noexcept
            {
                return error_message_.c_str();
            }
        } // namespace exception
    } // namespace magic
} // namespace engine