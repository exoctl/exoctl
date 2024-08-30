#pragma once

#include <engine/parser/json.hxx>
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
                       std::variant<int, double, std::string, const char *>>
        m_fields;

    mutable Parser::Json m_json;

  public:
    template <typename T>
    void dto_set_field(const std::string &p_field_name, const T &p_value)
    {
        m_fields[p_field_name] = p_value;
    }

    template <typename T> T dto_get_field(const std::string &p_field_name) const
    {
        auto it = m_fields.find(p_field_name);
        if (it != m_fields.end())
            return std::get<T>(it->second);

        throw std::invalid_argument("Field not found: " + p_field_name);
    }

    Parser::Json dto_to_json() const
    {
        for (const auto &[key, value] : m_fields)
        {
            std::visit([this, &key](const auto &arg) { m_json[key] = arg; },
                       value);
        }

        return m_json;
    }

    virtual ~DTOBase() = default;
};
} // namespace DTO