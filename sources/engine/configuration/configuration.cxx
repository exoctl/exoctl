#include <engine/configuration/configuration.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine
{
    namespace configuration
    {
        void Configuration::bind_to_lua(sol::state_view &p_lua)
        {
            p_lua.new_enum<toml::node_type>(
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
                                 const toml::node_type type) -> sol::object {
                    auto &lua = plugins::Plugins::lua.state;
                    auto node = self.get(section);

                    switch (type) {
                        case toml::node_type::string:
                            return sol::make_object(
                                lua, node.value<std::string>().value());
                        case toml::node_type::integer:
                            return sol::make_object(
                                lua, node.value<int64_t>().value());
                        case toml::node_type::boolean:
                            return sol::make_object(lua,
                                                    node.value<bool>().value());
                        case toml::node_type::floating_point:
                            return sol::make_object(
                                lua, node.value<double>().value());
                        case toml::node_type::array: {
                            if (!node.is_array()) {
                                throw exception::Get("Type mismatch for key: " +
                                                     section);
                            }

                            sol::table luaTable = lua.create_table();
                            size_t index = 1;
                            for (const auto &elem : *node.as_array()) {
                                if (auto val = elem.value<std::string>()) {
                                    luaTable[index] = *val;
                                } else if (auto val = elem.value<int64_t>()) {
                                    luaTable[index] = *val;
                                } else if (auto val = elem.value<bool>()) {
                                    luaTable[index] = *val;
                                } else if (auto val = elem.value<double>()) {
                                    luaTable[index] = *val;
                                } else {
                                    luaTable[index] = sol::nil;
                                }
                                index++;
                            }
                            return sol::make_object(lua, luaTable);
                        }
                        default:
                            throw exception::Get("Unsupported type for key: " +
                                                 section);
                    }
                }));
        }

        void Configuration::setup(const std::string &p_path)
        {
            m_path.assign(p_path);
        }

#ifdef ENGINE_PRO
        void Configuration::register_plugins()
        {
            Configuration::bind_to_lua(plugins::Plugins::lua.state);
        }

#endif

        void Configuration::load()
        {
            TRY_BEGIN()

            m_toml = toml::parse_file(m_path);

            TRY_END()
            CATCH(toml::parse_error, {
                const auto &source = e.source();
                throw exception::Load(
                    fmt::format("Error parsing file '{:s}' at line {:d}, "
                                "column {:d}: {:s}",
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

        toml::node_view<const toml::node> Configuration::get(
            const std::string &path) const
        {
            auto node = m_toml.at_path(path);
            if (!node) {
                throw exception::Get("Section or key not found: " + path);
            }
            return node;
        }

        Configuration &Configuration::operator=(const Configuration &p_config)
        {
            if (this != &p_config) {
                m_path = p_config.m_path;
                m_toml = p_config.m_toml;
            }
            return *this;
        }
    } // namespace configuration
} // namespace engine