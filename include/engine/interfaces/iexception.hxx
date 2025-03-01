#pragma once

#include <exception>
#include <string>

#define RETHROW() std::rethrow_exception(std::current_exception())

#define TRY_BEGIN() try {
#define CATCH(exception_type, action)                                          \
    catch (const exception_type &e)                                            \
    {                                                                          \
        action;                                                                \
    }
#define TRY_END() }

namespace engine::interface
{
    class IException : public std::exception
    {
      protected:
        explicit IException() = default;

      public:
        ~IException() override = default;
        [[nodiscard]] auto what() const noexcept -> const char * override = 0;
    };
} // namespace engine::interface
