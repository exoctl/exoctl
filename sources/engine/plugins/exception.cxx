#include <engine/plugins/exception.hxx>

namespace engine
{
    namespace plugins
    {
        namespace exception
        {
            LoadPlugin::LoadPlugin(const std::string &p_message)
                : error_message_(p_message)
            {
            }

            const char *LoadPlugin::what() const noexcept
            {
                return error_message_.c_str();
            }

            LoadLibraries::LoadLibraries(const std::string &p_message)
                : error_message_(p_message)
            {
            }

            const char *LoadLibraries::what() const noexcept
            {
                return error_message_.c_str();
            }

            Runtime::Runtime(const std::string &p_message)
                : error_message_(p_message)
            {
            }

            const char *Runtime::what() const noexcept
            {
                return error_message_.c_str();
            }

        } // namespace exception
    } // namespace plugins
} // namespace engine