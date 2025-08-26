#pragma once

#include <engine/parser/json/json.hxx>
#include <string>

namespace engine::interface
{
    template <typename Derived> class IResponse
    {
      public:
        explicit IResponse(const std::string &p_status = "", int p_code = -1)
            : code_(p_code), status_(p_status)
        {
        }

        virtual ~IResponse() = default;

        template <typename T>
        inline Derived &add_field(const std::string &key, const T &value)
        {
            json_.add(key, value);
            return *static_cast<Derived *>(this);
        }

        inline const parser::json::Json tojson() const
        {
            parser::json::Json json_data = json_;

            json_data.add("code", code());
            json_data.add("status", status());

            return json_data;
        }

        inline const int code() const
        {
            return (code_ == -1) ? static_cast<const Derived *>(this)->_code()
                                  : code_;
        }

        inline const std::string status() const
        {
            return status_.empty()
                       ? static_cast<const Derived *>(this)->_status()
                       : status_;
        }

      protected:
        int code_;
        std::string status_;
        parser::json::Json json_;

      private:
        virtual const int _code() const = 0;
        virtual const std::string _status() const = 0;
    };
} // namespace engine::interface
