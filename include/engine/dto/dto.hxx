#pragma once

#include <engine/dto/dto_exception.hxx>
#include <engine/parser/json.hxx>
#include <map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>

namespace DTO
{
    class DTOBase
    {
      private:
        std::unordered_map<std::string,
                           std::variant<int,
                                        double,
                                        std::string,
                                        const char *,
                                        Parser::Json,
                                        uint64_t>>
            m_fields;

        mutable Parser::Json m_json;

      public:
        ~DTOBase();
        DTOBase();

        template <typename T>
        void dto_set_field(const std::string &p_field_name, const T &p_value)
        {
            m_fields[p_field_name] = p_value;
        }

        template <typename T>
        T dto_get_field(const std::string &p_field_name) const
        {
            if (m_fields.contains(p_field_name))
                return std::get<T>(m_fields.at(p_field_name));

            throw DTOException::Field("Field not found: " + p_field_name);
        }

        const Parser::Json dto_to_json() const;
    };
} // namespace DTO