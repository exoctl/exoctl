#include <engine/parser/json/json.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::parser::json
{
    Json::Json()
    {
        document.SetObject();
    }

    Json::Json(const parser::json::Json &other)
    {
        document.CopyFrom(other.document, m_allocator);
    }

    void Json::clear()
    {
        document.Clear();
    }

    void Json::from_string(const std::string &json_str)
    {
        document.Parse(json_str.c_str());
    }

    Json &Json::operator=(const Json &other)
    {
        if (this != &other) {
            document.SetObject();
            document.CopyFrom(other.document, document.GetAllocator());
        }
        return *this;
    }

    std::string Json::tostring() const
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);
        return buffer.GetString();
    }
} // namespace engine::parser::json
