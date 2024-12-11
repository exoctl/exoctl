#pragma once

#pragma once

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