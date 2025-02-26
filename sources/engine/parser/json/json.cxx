#include <engine/parser/json/json.hxx>
#include <engine/plugins/plugins.hxx>
#include <iostream>

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

#ifdef ENGINE_PRO
        void Json::_plugins()
        {
            plugins::Plugins::lua.state.new_usertype<parser::Json>(
                "Json",
                sol::constructors<Json(), Json(const parser::Json &)>(),
                "from_string",
                &Json::from_string,
                "to_string",
                &Json::to_string,
                "add_member",
                sol::overload(
                    [](engine::parser::Json &self,
                       const std::string &key,
                       const std::string &value) {
                        self.add_member(key, value);
                    },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       int64_t value) { self.add_member(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       bool value) { self.add_member(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       double value) { self.add_member(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       sol::table value) {
                        std::vector<engine::parser::Json> vec;
                        for (auto &item : value) {
                            if (item.second.is<engine::parser::Json>()) {
                                vec.push_back(
                                    item.second.as<engine::parser::Json>());
                            }
                        }
                        self.add_member(key, vec);
                    }));
        }
#endif

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