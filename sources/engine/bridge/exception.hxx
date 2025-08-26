#pragma once

#include <engine/exception.hxx>

namespace engine
{
    namespace bridge
    {
        namespace exception
        {
            class Abort : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit Abort(const std::string &);
                const char *what() const noexcept override;
            };

            class ParcialAbort : public interface::IException
            {
              private:
                const std::string error_message_;

              public:
                explicit ParcialAbort(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace bridge
} // namespace engine