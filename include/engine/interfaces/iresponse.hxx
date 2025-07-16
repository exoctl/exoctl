#pragma once

#include <engine/parser/json/json.hxx>

namespace engine::interface
{
    // CRTP (Curiously Recurring Template Pattern)
    template <typename Derived> class IResponse
    {
      public:
        inline static const parser::Json to_json()
        {
            return Derived()._tojson();
        }

        inline static const int code()
        {
            return Derived()._code();
        }

        inline static const std::string status()
        {
            return Derived()._status();
        }

        inline static const std::string message()
        {
            return Derived()._message();
        }

        virtual ~IResponse() = default;
        explicit IResponse() = default;

      private:
        virtual const parser::Json _tojson() const = 0;
        virtual const int _code() const = 0;
        virtual const std::string _status() const = 0;
        virtual const std::string _message() const = 0;
    };
} // namespace engine::interface
