#pragma once

#include <engine/parser/json/json.hxx>
#include <string>

namespace engine::interface
{
    template <typename Derived> class IResponse
    {
      public:
        explicit IResponse(const std::string &p_status = "", int p_code = -1)
            : m_code(p_code), m_status(p_status)
        {
        }

        virtual ~IResponse() = default;

        template <typename T>
        inline Derived &add_field(const std::string &key, const T &value)
        {
            m_json.add(key, value);
            return *static_cast<Derived *>(this);
        }

        inline const parser::Json tojson() const
        {
            parser::Json json_data = m_json;

            json_data.add("code", code());
            json_data.add("status", status());

            return json_data;
        }

        inline const int code() const
        {
            return (m_code == -1) ? static_cast<const Derived *>(this)->_code()
                                  : m_code;
        }

        inline const std::string status() const
        {
            return m_status.empty()
                       ? static_cast<const Derived *>(this)->_status()
                       : m_status;
        }

      protected:
        int m_code;
        std::string m_status;
        parser::Json m_json;

      private:
        virtual const int _code() const = 0;
        virtual const std::string _status() const = 0;
    };
} // namespace engine::interface
