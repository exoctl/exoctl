#ifdef ENGINE_PRO

#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/yara/extend/yara.hxx>
#include <engine/security/yara/yara.hxx>

namespace engine::security::yara::extend
{
    void Yara::bind_import()
    {
        plugins::Plugins::lua.state.new_usertype<YR_MODULE_IMPORT>(
            "Import",
            sol::constructors<YR_MODULE_IMPORT()>(),
            "module_name",
            sol::readonly(&YR_MODULE_IMPORT::module_name));
    }

    void Yara::bind_string()
    {
        plugins::Plugins::lua.state.new_usertype<YR_STRING>(
            "String",
            sol::constructors<YR_STRING()>(),
            "flags",
            sol::readonly(&YR_STRING::flags),
            "idx",
            sol::readonly(&YR_STRING::idx),
            "fixed_offset",
            sol::readonly(&YR_STRING::fixed_offset),
            "rule_idx",
            sol::readonly(&YR_STRING::rule_idx),
            "length",
            sol::readonly(&YR_STRING::length),
            "string",
            [](const YR_STRING &s) {
                return std::string(reinterpret_cast<const char *>(s.string),
                                   s.length);
            },
            "identifier",
            sol::readonly(&YR_STRING::identifier));
    }

    void Yara::bind_namespace()
    {
        plugins::Plugins::lua.state.new_usertype<YR_NAMESPACE>(
            "Namespace",
            sol::constructors<YR_NAMESPACE()>(),
            "name",
            sol::readonly(&YR_NAMESPACE::name),
            "idx",
            sol::readonly(&YR_NAMESPACE::idx));
    }

    void Yara::bind_meta()
    {
        plugins::Plugins::lua.state.new_usertype<YR_META>(
            "Meta",
            sol::constructors<YR_META()>(),
            "flags",
            sol::readonly(&YR_META::flags),
            "type",
            sol::readonly(&YR_META::type),
            "identifier",
            sol::readonly(&YR_META::identifier),
            "integer",
            sol::readonly(&YR_META::integer),
            "string",
            sol::readonly(&YR_META::string));
    }

    void Yara::bind_rule()
    {
        plugins::Plugins::lua.state.new_usertype<YR_RULE>(
            "Rule",
            sol::constructors<YR_RULE()>(),
            "flags",
            sol::readonly(&YR_RULE::flags),
            "num_atoms",
            sol::readonly(&YR_RULE::num_atoms),
            "required_strings",
            sol::readonly(&YR_RULE::required_strings),
            "identifier",
            sol::readonly(&YR_RULE::identifier),
            "tags",
            sol::readonly(&YR_RULE::tags),
            "ns",
            sol::readonly(&YR_RULE::ns),
            "strings",
            sol::readonly(&YR_RULE::strings),
            "metas",
            sol::readonly(&YR_RULE::metas));
    }

    void Yara::bind_stream()
    {
        plugins::Plugins::lua.state.new_usertype<YR_STREAM>(
            "Stream",
            sol::constructors<YR_STREAM()>(),
            "read",
            [](YR_STREAM &stream, sol::function func) {
                static sol::function lua_read_func = func;
                stream.read =
                    [](void *ptr, size_t size, size_t count, void *) -> size_t {
                    if (!lua_read_func.valid()) {
                        throw plugins::exception::Runtime("Callback not valid");
                    }

                    sol::protected_function_result result = lua_read_func(
                        std::string(static_cast<const char *>(ptr),
                                    size * count),
                        size,
                        count);
                    if (!result.valid()) {
                        sol::error err = result;
                        throw plugins::exception::Runtime(
                            fmt::format("Lua callback error : {}", err.what()));
                    }
                    return result;
                };
            },
            "write",
            [](YR_STREAM &stream, sol::function func) {
                static sol::function lua_write_func = func;
                stream.write = [](const void *ptr,
                                  const size_t size,
                                  const size_t count,
                                  void *) -> size_t {
                    if (!lua_write_func.valid()) {
                        throw plugins::exception::Runtime("Callback not valid");
                    }

                    sol::protected_function_result result = lua_write_func(
                        std::string(static_cast<const char *>(ptr),
                                    size * count),
                        size,
                        count);
                    if (!result.valid()) {
                        sol::error err = result;
                        throw plugins::exception::Runtime(fmt::format(
                            "Lua callback error in : {}", err.what()));
                    }
                    return result;
                };
            });
    }

    void Yara::bind_data()
    {
        plugins::Plugins::lua.state.new_usertype<yara::record::Data>(
            "Data",
            "match_status",
            sol::readonly(&yara::record::Data::match_status),
            "rule",
            sol::readonly(&yara::record::Data::rule),
            "ns",
            sol::readonly(&yara::record::Data::ns));
    }

    void Yara::bind_yara()
    {
        plugins::Plugins::lua.state.new_usertype<engine::security::Yara>(
            "Yara",
            sol::constructors<engine::security::Yara()>(),
            "unload_stream_rules",
            &engine::security::Yara::unload_stream_rules,
            "load_stream_rules",
            &engine::security::Yara::load_stream_rules,
            "rules_foreach",
            &engine::security::Yara::rules_foreach,
            "metas_foreach",
            &engine::security::Yara::metas_foreach,
            "tags_foreach",
            &engine::security::Yara::tags_foreach,
            "strings_foreach",
            &engine::security::Yara::strings_foreach,
            "save_stream_rules",
            &engine::security::Yara::save_stream_rules,
            "load_compiler",
            &engine::security::Yara::load_compiler,
            "unload_compiler",
            &engine::security::Yara::unload_compiler,
            "load_rules_folder",
            &engine::security::Yara::load_rules_folder,
            "load_rules",
            &engine::security::Yara::load_rules,
            "scan_bytes",
            [](engine::security::Yara &self,
               const std::string &buffer,
               sol::function func,
               int flags) {
                if (!func.valid()) {
                    return;
                }

                static sol::function scan_bytes_func = func;
                self.scan_bytes(
                    buffer,
                    +[](YR_SCAN_CONTEXT *context,
                        int message,
                        void *message_data,
                        void *user_data) -> int {
                        sol::protected_function_result result;
                        switch (message) {
                            case CALLBACK_MSG_RULE_NOT_MATCHING:
                            case CALLBACK_MSG_RULE_MATCHING: {
                                const YR_RULE *rule =
                                    reinterpret_cast<YR_RULE *>(message_data);
                                result = scan_bytes_func(message, rule);
                                break;
                            }
                            case CALLBACK_MSG_SCAN_FINISHED:
                                result = scan_bytes_func(message,
                                                         sol::type::lua_nil);
                                break;
                            case CALLBACK_MSG_TOO_MANY_MATCHES: {
                                const YR_STRING *string =
                                    reinterpret_cast<YR_STRING *>(message_data);
                                result = scan_bytes_func(message, string);
                                break;
                            }
                            case CALLBACK_MSG_CONSOLE_LOG: {
                                const char *log =
                                    reinterpret_cast<const char *>(
                                        message_data);
                                result = scan_bytes_func(message, log);
                                break;
                            }
                            case CALLBACK_MSG_IMPORT_MODULE: {
                                const YR_MODULE_IMPORT *module_import =
                                    reinterpret_cast<YR_MODULE_IMPORT *>(
                                        message_data);
                                result =
                                    scan_bytes_func(message, module_import);
                                break;
                            }
                            default:
                                result = scan_bytes_func(message);
                                break;
                        }
                        if (!result.valid()) {
                            sol::error err = result;
                            throw plugins::exception::Runtime(fmt::format(
                                "Lua callback error in : {}\n", err.what()));
                            return CALLBACK_ABORT;
                        }
                        return result;
                    },
                    nullptr,
                    flags);
            },
            "scan_fast_bytes",
            &engine::security::Yara::scan_fast_bytes,
            "rules_loaded_count",
            &engine::security::Yara::rules_loaded_count,
            "load_rule_file",
            &engine::security::Yara::load_rule_file,
            "load_rule_buff",
            &engine::security::Yara::load_rule_buff);
    }

    void Yara::_plugins()
    {
        Yara::bind_import();
        Yara::bind_string();
        Yara::bind_namespace();
        Yara::bind_meta();
        Yara::bind_rule();
        Yara::bind_stream();
        Yara::bind_data();
        Yara::bind_yara();
    }
} // namespace engine::security::yara::extend

#endif