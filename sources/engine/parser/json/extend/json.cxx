#ifdef ENGINE_PRO

#include <engine/parser/json/extend/json.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::parser::extend
{
    void Json::bind_json()
    {
        plugins::Plugins::lua.state.new_usertype<parser::Json>(
            "Json",
            sol::constructors<Json(), Json(const parser::Json &)>(),
            "from_string",
            &parser::Json::from_string,
            "to_string",
            &parser::Json::to_string,
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

    void Json::_plugins()
    {
        Json::bind_json();
    }
} // namespace engine::parser::extend

#endif