#include <engine/exception.hxx>

namespace engine::exception
{
    Run::Run(const std::string &p_message) : error_message_(p_message)
    {
    }

    const char *Run::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::exception
