#pragma once

#include <engine/interfaces/iexception.hxx>
#include <string>

namespace engine
{
    namespace decompiler
    {
        namespace llama
        {
            class Initialize : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit Initialize(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace llama
    } // namespace decompiler
} // namespace engine