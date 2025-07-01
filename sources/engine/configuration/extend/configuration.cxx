#include <engine/configuration/configuration.hxx>
#include <engine/configuration/extend/configuration.hxx>
#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>

namespace engine::configuration::extend
{
    void Configuration::bind_configuration(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<configuration::Configuration>(
            "Configuration",
            "new",
            sol::constructors<configuration::Configuration()>(),
            "load",
            &configuration::Configuration::load,
            "setup",
            &configuration::Configuration::setup,
            "get",
            sol::overload([](configuration::Configuration &self,
                             const std::string &section) -> sol::object {
                auto node = self.get(section);

                if (!node) {
                    throw plugins::exception::Runtime(
                        fmt::format("Key not found: {}", section));
                }

                if (node.is_string()) {
                    return sol::make_object(plugins::Plugins::lua.state,
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
                            luaTable[key.str()] = value.value<bool>().value();
                        } else if (value.is_floating_point()) {
                            luaTable[key.str()] = value.value<double>().value();
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
                    throw plugins::exception::Runtime(
                        fmt::format("Unsupported type for key: {}", section));
                }
            }));
    }

    void Configuration::lua_open_library(engine::lua::StateView &p_lua)
    {
        Configuration::bind_configuration(p_lua);
    }

    void Configuration::_plugins()
    {
        Configuration::bind_configuration(plugins::Plugins::lua.state);
    }
} // namespace engine::configuration::extend