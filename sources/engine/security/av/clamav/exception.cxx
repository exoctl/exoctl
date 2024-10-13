#include <engine/security/av/clamav/exception.hxx>

namespace engine
{
    namespace security
    {
        namespace av
        {
            namespace clamav
            {

                namespace exception
                {
                    Initialize::Initialize(const std::string &p_message)
                        : m_error_message(p_message)
                    {
                    }
                    const char *Initialize::what() const noexcept
                    {
                        return m_error_message.c_str();
                    }

                    LoadRules::LoadRules(const std::string &p_message)
                        : m_error_message(p_message)
                    {
                    }
                    const char *LoadRules::what() const noexcept
                    {
                        return m_error_message.c_str();
                    }

                    SetDbRules::SetDbRules(const std::string &p_message)
                        : m_error_message(p_message)
                    {
                    }
                    const char *SetDbRules::what() const noexcept
                    {
                        return m_error_message.c_str();
                    }
                } // namespace exception
            } // namespace clamav
        } // namespace av
    } // namespace security
} // namespace engine