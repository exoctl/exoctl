#pragma once

#include <engine/interfaces/iexception.hxx>

namespace security
{
    namespace clamav
    {
        namespace exception
        {
            class Initialize : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit Initialize(const std::string &);
                const char *what() const noexcept override;
            };

            class LoadRules : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit LoadRules(const std::string &);
                const char *what() const noexcept override;
            };

            class SetDbRules : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit SetDbRules(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace clamav
} // namespace security