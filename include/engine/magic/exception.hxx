#pragma once

#include <engine/interfaces/iexception.hxx>
#include <string>

namespace engine
{
    namespace magic
    {
        namespace exception
        {
            class Initialize : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit Initialize(const std::string &);
                const char *what() const noexcept override;
            };

            class Finalize : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit Finalize(const std::string &);
                const char *what() const noexcept override;
            };

        } // namespace exception
    } // namespace magic
} // namespace engine