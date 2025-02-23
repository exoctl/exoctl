#include <engine/configuration/configuration.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine
{
    namespace configuration
    {
        void Configuration::bind_to_lua(sol::state_view &p_lua)
        {
            plugins::Plugins::lua.state.new_enum<toml::node_type>(
                "NodeType",
                {{"array", toml::node_type::array},
                 {"string", toml::node_type::string},
                 {"integer", toml::node_type::integer},
                 {"floating_point", toml::node_type::floating_point},
                 {"boolean", toml::node_type::boolean}});

            p_lua.new_usertype<configuration::Configuration>(
                "Configuration",
                sol::constructors<configuration::Configuration()>(),
                "load",
                &Configuration::load,
#ifdef ENGINE_PRO
                "register_plugins",
                &Configuration::register_plugins,
#endif
                "setup",
                Configuration::setup,
                "get",
                sol::overload([](configuration::Configuration &self,
                                 const std::string &section,
                                 const int type) -> sol::object {
                    auto &lua = plugins::Plugins::lua.state;
                    switch (type) {
                        case 0:
                            return sol::make_object(
                                lua, self.get<std::string>(section));
                        case 1:
                            return sol::make_object(lua,
                                                    self.get<int64_t>(section));
                        case 2:
                            return sol::make_object(lua,
                                                    self.get<bool>(section));
                        case 3: {
                            auto vec = self.get<std::vector<std::any>>(section);
                            sol::table luaTable = lua.create_table();
                            for (size_t i = 0; i < vec.size(); ++i) {
                                const auto &elem = vec[i];
                                if (elem.type() == typeid(std::string)) {
                                    luaTable[i + 1] =
                                        std::any_cast<std::string>(elem);
                                } else if (elem.type() == typeid(int64_t)) {
                                    luaTable[i + 1] =
                                        std::any_cast<int64_t>(elem);
                                } else if (elem.type() == typeid(bool)) {
                                    luaTable[i + 1] = std::any_cast<bool>(elem);
                                } else {
                                    luaTable[i + 1] = sol::nil;
                                }
                            }
                            return sol::make_object(lua, luaTable);
                        }
                        default:
                            throw std::runtime_error("Type not supported");
                    }
                }));
        }

        void Configuration::setup(const std::string &p_path)
        {
            m_path.assign(p_path);
            m_toml.parse_file(m_path);
        }

#ifdef ENGINE_PRO
        void Configuration::register_plugins()
        {
            plugins::Plugins::lua.state.new_enum<toml::node_type>(
                "node_type",
                {{"array", toml::node_type::array},
                 {"string", toml::node_type::string},
                 {"integer", toml::node_type::integer},
                 {"floating_point", toml::node_type::floating_point},
                 {"boolean", toml::node_type::boolean}});

            plugins::Plugins::lua.state
                .new_usertype<configuration::Configuration>(
                    "Configuration",
                    "setup",
                    &configuration::Configuration::setup,
                    "load",
                    &Configuration::load,
                    "get",
                    sol::overload([](configuration::Configuration &self,
                                     const std::string &section,
                                     toml::node_type type) -> sol::object {
                        auto &lua = plugins::Plugins::lua.state;
                        switch (type) {
                            case toml::node_type::string:
                                return sol::make_object(
                                    lua, self.get<std::string>(section));
                            case toml::node_type::integer:
                                return sol::make_object(
                                    lua, self.get<int64_t>(section));
                            case toml::node_type::boolean:
                                return sol::make_object(
                                    lua, self.get<bool>(section));
                            case toml::node_type::array: {
                                auto vec =
                                    self.get<std::vector<std::any>>(section);
                                sol::table luaTable = lua.create_table();
                                for (size_t i = 0; i < vec.size(); ++i) {
                                    const auto &elem = vec[i];
                                    if (elem.type() == typeid(std::string)) {
                                        luaTable[i + 1] =
                                            std::any_cast<std::string>(elem);
                                    } else if (elem.type() == typeid(int64_t)) {
                                        luaTable[i + 1] =
                                            std::any_cast<int64_t>(elem);
                                    } else if (elem.type() == typeid(bool)) {
                                        luaTable[i + 1] =
                                            std::any_cast<bool>(elem);
                                    } else {
                                        luaTable[i + 1] = sol::nil;
                                    }
                                }
                                return sol::make_object(lua, luaTable);
                            }
                            default:
                                throw std::runtime_error("Type not supported");
                        }
                    }));
        }

#endif

        void Configuration::load()
        {
            TRY_BEGIN()

            dynamic_configs.clear();

            std::function<void(const toml::table &,
                               std::unordered_map<std::string, std::any> &)>
                process_table;
            process_table =
                [&process_table](
                    const toml::table &table,
                    std::unordered_map<std::string, std::any> &section_data) {
                    for (const auto &[key, value] : table) {
                        std::string key_str = std::string(key);
                        if (value.is_string()) {
                            section_data[key_str] = value.as_string()->get();
                        } else if (value.is_integer()) {
                            section_data[key_str] = value.as_integer()->get();
                        } else if (value.is_boolean()) {
                            section_data[key_str] = value.as_boolean()->get();
                        } else if (value.is_floating_point()) {
                            section_data[key_str] =
                                value.as_floating_point()->get();
                        } else if (value.is_array()) {
                            std::vector<std::any> array_values;
                            for (const auto &elem : *value.as_array()) {
                                if (elem.is_string()) {
                                    array_values.push_back(
                                        elem.as_string()->get());
                                } else if (elem.is_integer()) {
                                    array_values.push_back(
                                        elem.as_integer()->get());
                                } else if (elem.is_floating_point()) {
                                    array_values.push_back(
                                        elem.as_floating_point()->get());
                                } else if (elem.is_boolean()) {
                                    array_values.push_back(
                                        elem.as_boolean()->get());
                                }
                            }
                            section_data[key_str] = array_values;
                        } else if (value.is_table()) {
                            std::unordered_map<std::string, std::any>
                                sub_section_data;
                            process_table(*value.as_table(), sub_section_data);
                            section_data[key_str] = sub_section_data;
                        }
                    }
                };

            process_table(m_toml.tbl, dynamic_configs);

            TRY_END()
            CATCH(toml::parse_error, {
                const auto &source = e.source();
                throw exception::Load(fmt::format(
                    "Error parsing file '{:s}' at line {:d}, column {:d}: {:s}",
                    *source.path,
                    source.begin.line,
                    source.begin.column,
                    e.description()));
            })
            CATCH(std::exception, {
                throw exception::Load(
                    fmt::format("Unexpected error: {:s}", e.what()));
            });
        }

        Configuration &Configuration::operator=(const Configuration &p_config)
        {
            if (this != &p_config) {
                m_path = p_config.m_path;
                dynamic_configs = p_config.dynamic_configs;
                m_toml = p_config.m_toml;
            }
            return *this;
        }
    } // namespace configuration
} // namespace engine