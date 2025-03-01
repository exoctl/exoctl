#ifdef ENGINE_PRO

#include <engine/plugins/exception.hxx>

namespace engine
{
    namespace plugins
    {
        namespace exception
        {
            LoadPlugin::LoadPlugin(const std::string &p_message)
                : m_error_message(p_message)
            {
            }

            const char *LoadPlugin::what() const noexcept
            {
                return m_error_message.c_str();
            }

            LoadLibraries::LoadLibraries(const std::string &p_message)
                : m_error_message(p_message)
            {
            }

            const char *LoadLibraries::what() const noexcept
            {
                return m_error_message.c_str();
            }

            Runtime::Runtime(const std::string &p_message)
                : m_error_message(p_message)
            {
            }

            const char *Runtime::what() const noexcept
            {
                return m_error_message.c_str();
            }

        } // namespace exception
    } // namespace plugins
} // namespace engine

#endif