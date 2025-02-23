#include <engine/security/yara/exception.hxx>

namespace engine
{
    namespace security
    {
        namespace yara
        {
            namespace exception
            {
                CompilerRules::CompilerRules(const std::string &p_message)
                    : m_error_message(p_message)
                {
                }
                const char *CompilerRules::what() const noexcept
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

                Initialize::Initialize(const std::string &p_message)
                    : m_error_message(p_message)
                {
                }
                const char *Initialize::what() const noexcept
                {
                    return m_error_message.c_str();
                }

                Finalize::Finalize(const std::string &p_message)
                    : m_error_message(p_message)
                {
                }
                const char *Finalize::what() const noexcept
                {
                    return m_error_message.c_str();
                }

                Unload::Unload(const std::string &p_message)
                    : m_error_message(p_message)
                {
                }
                const char *Unload::what() const noexcept
                {
                    return m_error_message.c_str();
                }

                Scan::Scan(const std::string &p_message)
                    : m_error_message(p_message)
                {
                }
                const char *Scan::what() const noexcept
                {
                    return m_error_message.c_str();
                }
            } // namespace exception
        } // namespace yara
    } // namespace security
} // namespace engine