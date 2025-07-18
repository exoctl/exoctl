#pragma once

#include <engine/interfaces/iexception.hxx>
#include <string>

namespace engine
{
    namespace security
    {
        namespace yara
        {
            namespace exception
            {
                class CompilerRules : public interface::IException
                {
                  private:
                    const std::string m_error_message;

                  public:
                    explicit CompilerRules(const std::string &);
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

                class Unload : public interface::IException
                {
                  private:
                    const std::string m_error_message;

                  public:
                    explicit Unload(const std::string &);
                    const char *what() const noexcept override;
                };

                class Initialize : public interface::IException
                {
                  private:
                    const std::string m_error_message;

                  public:
                    explicit Initialize(const std::string &);
                    const char *what() const noexcept override;
                };

                class Finalize : public interface::IException
                {
                  private:
                    const std::string m_error_message;

                  public:
                    explicit Finalize(const std::string &);
                    const char *what() const noexcept override;
                };

                class Scan : public interface::IException
                {
                  private:
                    const std::string m_error_message;

                  public:
                    explicit Scan(const std::string &);
                    const char *what() const noexcept override;
                };

            } // namespace exception
        } // namespace yara
    } // namespace security
} // namespace engine