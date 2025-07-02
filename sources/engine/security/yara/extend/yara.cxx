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
            "new",
            sol::constructors<YR_MODULE_IMPORT()>(),
            "module_name",
            sol::readonly(&YR_MODULE_IMPORT::module_name));
    }

    void Yara::bind_string()
    {
        plugins::Plugins::lua.state.new_usertype<YR_STRING>(
            "String",
            "new",
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
            "new",
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
            "new",
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
            "new",
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
            "new",
            sol::constructors<YR_STREAM()>(),
            "read",
            [](YR_STREAM &stream, sol::function func) {
                auto func_ptr =
                    std::make_shared<sol::function>(std::move(func));

                stream.user_data = static_cast<void *>(
                    new std::shared_ptr<sol::function>(func_ptr));

                stream.read = [](void *ptr,
                                 size_t size,
                                 size_t count,
                                 void *user_data) -> size_t {
                    if (!user_data) {
                        throw plugins::exception::Runtime(
                            "Callback not valid (null user_data)");
                    }

                    auto *func_shared_ptr =
                        static_cast<std::shared_ptr<sol::function> *>(
                            user_data);
                    sol::function &lua_read_func = **func_shared_ptr;

                    const size_t total_size = size * count;

                    sol::protected_function_result result =
                        lua_read_func(total_size);
                    if (!result.valid()) {
                        sol::error err = result;
                        throw plugins::exception::Runtime(
                            fmt::format("Lua callback error: {}", err.what()));
                    }

                    const std::string data = result.get<std::string>();
                    size_t bytes_read = std::min(total_size, data.size());

                    std::memcpy(ptr, data.data(), bytes_read);

                    return bytes_read / size;
                };
            },
            "write",
            [](YR_STREAM &stream, sol::function func) {
                auto func_ptr =
                    std::make_shared<sol::function>(std::move(func));

                stream.user_data = static_cast<void *>(
                    new std::shared_ptr<sol::function>(func_ptr));

                stream.write = [](const void *ptr,
                                  size_t size,
                                  size_t count,
                                  void *user_data) -> size_t {
                    if (!user_data) {
                        throw plugins::exception::Runtime(
                            "Callback not valid (null user_data)");
                    }

                    auto *func_shared_ptr =
                        static_cast<std::shared_ptr<sol::function> *>(
                            user_data);
                    sol::function &lua_write_func = **func_shared_ptr;

                    const size_t total_size = size * count;
                    std::string data(static_cast<const char *>(ptr),
                                     total_size);

                    sol::protected_function_result result =
                        lua_write_func(data);
                    if (!result.valid()) {
                        sol::error err = result;
                        throw plugins::exception::Runtime(
                            fmt::format("Lua callback error: {}", err.what()));
                    }

                    return count;
                };
            });
    }

    void Yara::bind_yara()
    {
        plugins::Plugins::lua.state.new_usertype<engine::security::Yara>(
            "Yara",
            "new",
            sol::constructors<engine::security::Yara()>(),
            "rule_disable",
            &engine::security::Yara::rule_disable,
            "rule_enable",
            &engine::security::Yara::rule_enable,
            "unload_rules",
            &engine::security::Yara::unload_rules,
            "load_rules_stream",
            &engine::security::Yara::load_rules_stream,
            "rules_foreach",
            &engine::security::Yara::rules_foreach,
            "metas_foreach",
            &engine::security::Yara::metas_foreach,
            "tags_foreach",
            &engine::security::Yara::tags_foreach,
            "strings_foreach",
            &engine::security::Yara::strings_foreach,
            "save_rules_stream",
            &engine::security::Yara::save_rules_stream,
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
                self.scan_bytes(
                    buffer,
                    +[](YR_SCAN_CONTEXT *context,
                        int message,
                        void *message_data,
                        void *user_data) -> int {
                        auto *scan_bytes_func =
                            static_cast<sol::function *>(user_data);
                        if (!scan_bytes_func || !scan_bytes_func->valid()) {
                            return CALLBACK_CONTINUE;
                        }

                        sol::protected_function_result result;
                        switch (message) {
                            case CALLBACK_MSG_RULE_NOT_MATCHING:
                            case CALLBACK_MSG_RULE_MATCHING: {
                                const YR_RULE *rule =
                                    reinterpret_cast<YR_RULE *>(message_data);
                                result = (*scan_bytes_func)(message, rule);
                                break;
                            }
                            case CALLBACK_MSG_SCAN_FINISHED:
                                result =
                                    (*scan_bytes_func)(message, sol::lua_nil);
                                break;
                            case CALLBACK_MSG_TOO_MANY_MATCHES: {
                                const YR_STRING *string =
                                    reinterpret_cast<YR_STRING *>(message_data);
                                result = (*scan_bytes_func)(message, string);
                                break;
                            }
                            case CALLBACK_MSG_CONSOLE_LOG: {
                                const char *log =
                                    reinterpret_cast<const char *>(
                                        message_data);
                                result = (*scan_bytes_func)(message, log);
                                break;
                            }
                            case CALLBACK_MSG_IMPORT_MODULE: {
                                const YR_MODULE_IMPORT *module_import =
                                    reinterpret_cast<YR_MODULE_IMPORT *>(
                                        message_data);
                                result =
                                    (*scan_bytes_func)(message, module_import);
                                break;
                            }
                            default:
                                result = (*scan_bytes_func)(message);
                                break;
                        }

                        if (!result.valid()) {
                            sol::error err = result;
                            throw plugins::exception::Runtime(fmt::format(
                                "Lua callback error in scan_bytes: {}\n",
                                err.what()));
                            return CALLBACK_ABORT;
                        }
                        return result;
                    },
                    static_cast<void *>(&func),
                    flags);
            },
            "load_rules_file",
            &engine::security::Yara::load_rules_file,
            "set_rule_buff",
            &engine::security::Yara::set_rule_buff,
            "set_rule_file",
            &engine::security::Yara::set_rule_file,
            "save_rules_file",
            &engine::security::Yara::save_rules_file);
    }

    void Yara::_plugins()
    {
        Yara::bind_import();
        Yara::bind_string();
        Yara::bind_namespace();
        Yara::bind_meta();
        Yara::bind_rule();
        Yara::bind_stream();
        Yara::bind_yara();
    }
} // namespace engine::security::yara::extend