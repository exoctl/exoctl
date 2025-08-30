#include <engine/bridge/exception.hxx>

namespace engine::bridge::exception
{
    Abort::Abort(const std::string &p_message) : error_message_(p_message)
    {
    }
    const char *Abort::what() const noexcept
    {
        return error_message_.c_str();
    }

    ParcialAbort::ParcialAbort(const std::string &p_message)
        : error_message_(p_message)
    {
    }
    const char *ParcialAbort::what() const noexcept
    {
        return error_message_.c_str();
    }

} // namespace engine::bridge::exception
