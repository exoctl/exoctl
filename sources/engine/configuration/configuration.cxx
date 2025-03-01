#include <engine/configuration/configuration.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine
{
    namespace configuration
    {
        void Configuration::bind_to_lua(sol::state_view &p_lua)
        {
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
                                 const std::string &section) -> sol::object {
                    auto node = self.get(section);

                    if (!node) {
                        throw exception::Get("Key not found: " + section);
                    }

                    if (node.is_string()) {
                        return sol::make_object(
                            plugins::Plugins::lua.state,
                            node.value<std::string>().value());
                    } else if (node.is_integer()) {
                        return sol::make_object(plugins::Plugins::lua.state,
                                                node.value<int64_t>().value());
                    } else if (node.is_boolean()) {
                        return sol::make_object(plugins::Plugins::lua.state,
                                                node.value<bool>().value());
                    } else if (node.is_floating_point()) {
                        return sol::make_object(plugins::Plugins::lua.state,
                                                node.value<double>().value());
                    } else if (node.is_array()) {
                        sol::table luaTable =
                            plugins::Plugins::lua.state.create_table();
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
                        return sol::make_object(plugins::Plugins::lua.state,
                                                luaTable);
                    } else if (node.is_table()) {
                        sol::table luaTable =
                            plugins::Plugins::lua.state.create_table();
                        for (const auto &[key, value] : *node.as_table()) {
                            if (value.is_string()) {
                                luaTable[key.str()] =
                                    value.value<std::string>().value();
                            } else if (value.is_integer()) {
                                luaTable[key.str()] =
                                    value.value<int64_t>().value();
                            } else if (value.is_boolean()) {
                                luaTable[key.str()] =
                                    value.value<bool>().value();
                            } else if (value.is_floating_point()) {
                                luaTable[key.str()] =
                                    value.value<double>().value();
                            } else {
                                luaTable[key.str()] = sol::nil;
                            }
                        }
                        return sol::make_object(plugins::Plugins::lua.state,
                                                luaTable);
                    } else if (node.is_date()) {
                        auto date = node.value<toml::date>().value();
                        return sol::make_object(plugins::Plugins::lua.state,
                                                fmt::format("{:04}-{:02}-{:02}",
                                                            date.year,
                                                            date.month,
                                                            date.day));
                    } else if (node.is_time()) {
                        auto time = node.value<toml::time>().value();
                        return sol::make_object(
                            plugins::Plugins::lua.state,
                            fmt::format("{:02}:{:02}:{:02}.{:03}",
                                        time.hour,
                                        time.minute,
                                        time.second,
                                        time.nanosecond / 1'000'000));
                    } else if (node.is_date_time()) {
                        auto dt = node.value<toml::date_time>().value();
                        return sol::make_object(
                            plugins::Plugins::lua.state,
                            fmt::format(
                                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{}",
                                dt.date.year,
                                dt.date.month,
                                dt.date.day,
                                dt.time.hour,
                                dt.time.minute,
                                dt.time.second,
                                dt.time.nanosecond / 1'000'000,
                                dt.offset ? fmt::format("{:+03}:{:02}",
                                                        dt.offset->minutes / 60,
                                                        dt.offset->minutes % 60)
                                          : "Z"));
                    } else {
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