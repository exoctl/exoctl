#pragma once

#include <engine/interfaces/iexception.hxx>

namespace security
{
    namespace sig
    {
        namespace exception
        {
            class CompilerSig : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit CompilerSig(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace sig
} // namespace security