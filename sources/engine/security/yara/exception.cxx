#include <engine/security/yara/exception.hxx>

namespace security
{
    namespace yara
    {
        namespace exception
        {
            CompilerRules::CompilerRules(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            LoadRules::LoadRules(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            Initialize::Initialize(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            Finalize::Finalize(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

            Scan::Scan(const std::string &p_message)
                : ::exception::Exception(p_message)
            {
            }

        } // namespace exception
    } // namespace yara
} // namespace security