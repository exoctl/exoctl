#include <engine/parser/json/json.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine
{
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

        void Json::clear()
        {
            m_document.Clear();
        }

        void Json::from_string(const std::string &json_str)
        {
            m_document.Parse(json_str.c_str());
        }

        std::string Json::to_string() const
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            m_document.Accept(writer);
            return buffer.GetString();
        }
    } // namespace parser
} // namespace engine