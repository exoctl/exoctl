#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine
{
    namespace lua
    {
        namespace exception
        {
            class RegisterClassMember : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit RegisterClassMember(const std::string &);
                const char *what() const noexcept override;
            };

            class RegisterClassMethod : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit RegisterClassMethod(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace lua
} // namespace engine