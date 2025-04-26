#pragma once

#if !defined(__arm__) || !defined(__aarch64__) || !defined(_M_ARM) ||          \
    !defined(_M_ARM64)

#include <engine/interfaces/iexception.hxx>
namespace engine
{
    namespace llama
    {
        namespace exception
        {
            class GenerateMessage : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit GenerateMessage(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace llama
} // namespace engine

#endif