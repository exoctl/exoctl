#pragma once

#include <exception>
#include <string>

#define TRY_BEGIN() try {

#define CATCH(exception_type, action)                                          \
    catch (const exception_type &e)                                            \
    {                                                                          \
        action;                                                                \
    }

#define TRY_END() }

namespace interface
{
    class IException : public std::exception
    {
      protected:
        explicit IException() = default;

      public:
        virtual ~IException() = default;
        virtual const char *what() const noexcept override = 0;
    };
} // namespace interface