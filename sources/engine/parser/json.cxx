#include <engine/parser/json.hxx>

namespace parser
{
    Json::Json()
    {
        m_document.SetObject();
    }

    Json::Json(const parser::Json &other)
    {
        m_document.CopyFrom(other.m_document, m_allocator);
    }

    Json::~Json()
    {
    }

    std::string Json::json_to_string() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        m_document.Accept(writer);
        return buffer.GetString();
    }

    void Json::json_add_member_string(const std::string &p_key,
                                      const std::string &p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        rapidjson::Value v(p_value.c_str(), m_allocator);
        m_document.AddMember(k, v, m_allocator);
    }

    void Json::json_add_member_int(const std::string &p_key, const int p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        m_document.AddMember(k, p_value, m_allocator);
    }

    void Json::json_add_member_uint16(const std::string &p_key,
                                      const uint16_t p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        m_document.AddMember(k, p_value, m_allocator);
    }

    void Json::json_add_member_uint64(const std::string &p_key,
                                      const uint64_t p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        m_document.AddMember(k, p_value, m_allocator);
    }

    void Json::json_add_member_double(const std::string &p_key,
                                      const double p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        m_document.AddMember(k, p_value, m_allocator);
    }

    void Json::json_add_member_bool(const std::string &p_key,
                                    const bool p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        m_document.AddMember(k, p_value, m_allocator);
    }

    void Json::json_add_member_json(const std::string &p_key,
                                    const Json &p_value)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        rapidjson::Value v;
        v.CopyFrom(p_value.m_document, m_allocator);
        m_document.AddMember(k, v, m_allocator);
    }

    void Json::json_add_member_vector(const std::string &p_key,
                                      const std::vector<Json> &p_values)
    {
        rapidjson::Value k(p_key.c_str(), m_allocator);
        rapidjson::Value array(rapidjson::kArrayType);

        for (const auto &value : p_values) {
            rapidjson::Value v;
            v.CopyFrom(value.m_document, m_allocator);
            array.PushBack(v, m_allocator);
        }

        m_document.AddMember(k, array, m_allocator);
    }

    rapidjson::Document &Json::json_get_document()
    {
        return m_document;
    }
} // namespace Parser