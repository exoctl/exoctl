#pragma once

#include <variant>
#include <unordered_map>
#include <string>
#include <stdexcept>
#include <engine/parser/json.hxx>

class DTOBase
{
private:
    /* TODO: Insert types for demand */
    std::unordered_map<std::string, std::variant<int, 
                                    double, 
                                    std::string, 
                                    const char*>> m_fields;

public:
    template <typename T>
    void dto_set_field(const std::string &p_field_name, const T &p_value)
    {
        m_fields[p_field_name] = p_value;
    }

    template <typename T>
    T dto_get_field(const std::string &p_field_name) const
    {
        auto it = m_fields.find(p_field_name);
        if (it != m_fields.end())
            return std::get<T>(it->second);

        throw std::invalid_argument("Field not found: " + p_field_name);
    }

    Parser::Json dto_to_json() const
    {
        Parser::Json json;

        for (const auto &[key, value] : m_fields)
        {
            std::visit([&json, &key](const auto& arg) {
                json[key] = arg;
            }, value);
        }

        return json;
    }

    virtual ~DTOBase() = default;
};
