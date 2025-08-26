#pragma once

#include <engine/interfaces/iexception.hxx>
namespace engine
{
    namespace configuration
    {
        namespace exception
        {
            class Load : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit Load(const std::string &);
                const char *what() const noexcept override;
            };

            class Get : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit Get(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace configuration
} // namespace engine