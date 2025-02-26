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
                "clear",
                &Json::clear,
                "get",
                sol::overload([](engine::parser::Json &self,
                                 const std::string &key) -> sol::object {
                    auto &lua = plugins::Plugins::lua.state;

                    auto make_lua_object = [&](auto value) -> sol::object {
                        return value ? sol::make_object(lua, *value)
                                     : sol::make_object(lua, sol::nil);
                    };

                    if (auto value = self.get<std::string>(key))
                        return make_lua_object(value);
                    if (auto value = self.get<int64_t>(key))
                        return make_lua_object(value);
                    if (auto value = self.get<engine::parser::Json>(key))
                        return make_lua_object(value);
                    if (auto value = self.get<bool>(key))
                        return make_lua_object(value);
                    if (auto value = self.get<double>(key))
                        return make_lua_object(value);
                    if (auto value =
                            self.get<std::vector<engine::parser::Json>>(key))
                        return make_lua_object(value);

                    return sol::make_object(lua, sol::nil);
                }),
                "add",
                sol::overload(
                    [](engine::parser::Json &self,
                       const std::string &key,
                       const std::string &value) { self.add(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       int64_t value) { self.add(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       engine::parser::Json value) { self.add(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       bool value) { self.add(key, value); },
                    [](engine::parser::Json &self,
                       const std::string &key,
                       double value) { self.add(key, value); },
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
                        self.add(key, vec);
                    }));
        }
#endif

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