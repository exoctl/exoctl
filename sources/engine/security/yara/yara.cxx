#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/security/yara/yara.hxx>
#include <fcntl.h>
#include <fmt/core.h>
#include <sys/types.h>
#include <unistd.h>

namespace engine
{
    namespace security
    {
        Yara::Yara()
            : rules_loaded_count(0), m_yara_compiler(nullptr),
              m_yara_rules(nullptr)
        {
            if (yr_initialize() != ERROR_SUCCESS) {
                throw yara::exception::Initialize(
                    "yr_initialize() error initialize yara");
            }

            const int yr_compiler = Yara::load_compiler();
            if (yr_compiler != ERROR_SUCCESS &&
                yr_compiler == ERROR_INSUFFICIENT_MEMORY) {
                throw yara::exception::Initialize(
                    "yr_compiler_create() error initialize compiler yara");
            }
        }

        const int Yara::load_compiler()
        {
            return yr_compiler_create(&m_yara_compiler);
        }

        void Yara::unload_compiler()
        {
            if (!IS_NULL(m_yara_compiler)) {
                yr_compiler_destroy(m_yara_compiler);
                m_yara_compiler = nullptr;
            }
        }

        void Yara::unload_stream_rules()
        {
            if (!IS_NULL(m_yara_rules)) {
                if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS) {
                    /* nothing */
                }
                m_yara_rules = nullptr;
            }
        }

        void Yara::rules_foreach(
            const std::function<void(const YR_RULE &)> &p_callback)
        {
            const YR_RULE *rule;
            yr_rules_foreach(m_yara_rules, rule)
            {
                p_callback(*rule);
            }
        }

        const int Yara::load_stream_rules(YR_STREAM &p_stream)
        {
            return yr_rules_load_stream(&p_stream, &m_yara_rules);
        }

        const int Yara::save_stream_rules(YR_STREAM &p_stream)
        {
            return yr_rules_save_stream(m_yara_rules, &p_stream);
        }

        Yara::~Yara()
        {
            if (yr_finalize() != ERROR_SUCCESS) {
                yara::exception::Finalize("yr_finalize() error finalize yara");
            }

            Yara::unload_compiler();
            Yara::unload_stream_rules();
        }

        const int Yara::load_rule_file(const std::string &p_path,
                                       const std::string &p_yrname,
                                       const std::string &p_yrns) const
        {
            const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);

            const int error_success = yr_compiler_add_fd(
                m_yara_compiler, rules_fd, p_yrns.c_str(), p_yrname.c_str());

            close(rules_fd);

            rules_loaded_count++;
            return error_success;
        }

        const int Yara::load_rule_buff(const std::string &p_rule,
                                       const std::string &p_yrns) const
        {
            rules_loaded_count++;
            return yr_compiler_add_string(
                m_yara_compiler, p_rule.c_str(), p_yrns.c_str());
        }

        void Yara::load_rules_folder(const std::string &p_path) const
        {
            DIR *dir = opendir(p_path.c_str());
            if (!dir)
                throw yara::exception::LoadRules(
                    fmt::format("{} : '{}'", strerror(errno), p_path));

            auto replace_slashes_with_dots =
                [](const std::string &str) -> std::string {
                std::string copy = str;
                std::replace(copy.begin(), copy.end(), '/', '.');

                return copy;
            };

            const struct dirent *entry;
            while ((entry = readdir(dir)) != nullptr) {
                const std::filesystem::path entry_name = entry->d_name;
                const std::string full_path =
                    fmt::format("{}/{}", p_path, entry_name.c_str());

                if (entry_name == "." || entry_name == "..") {
                    continue;
                }
                if (entry_name.extension() == ".yar") {
                    if (Yara::load_rule_file(full_path,
                                             entry_name,
                                             replace_slashes_with_dots(
                                                 p_path)) != ERROR_SUCCESS) {
                        throw yara::exception::LoadRules(
                            "yara_set_signature_rule() failed to compile "
                            "rule " +
                            std::string(full_path));
                    }
                } else if (entry->d_type == DT_DIR) {
                    load_rules_folder(full_path);
                }
            }
            closedir(dir);
        }

        void Yara::load_rules(const std::function<void()> &p_callback) const
        {
            if (!IS_NULL(p_callback)) {
                p_callback();
            }
            Yara::compiler_rules();
        }

        void Yara::compiler_rules() const
        {
            const int compiler_rules =
                yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
            if (compiler_rules != ERROR_SUCCESS ||
                compiler_rules == ERROR_INSUFFICIENT_MEMORY) {
                throw yara::exception::CompilerRules(
                    "yr_compiler_get_rules() falied compiler rules " +
                    compiler_rules);
            }
        }

        void Yara::scan_bytes(const std::string &p_buffer,
                              YR_CALLBACK_FUNC p_callback,
                              void *p_data,
                              int p_flags) const
        {
            if (m_yara_compiler != nullptr && m_yara_rules != nullptr) {
                if (yr_rules_scan_mem(
                        m_yara_rules,
                        reinterpret_cast<const uint8_t *>(p_buffer.c_str()),
                        p_buffer.size(),
                        p_flags,
                        p_callback,
                        p_data,
                        0) == ERROR_INTERNAL_FATAL_ERROR) {
                    throw yara::exception::Scan("yr_rules_scan_mem() falied "
                                                "scan buffer, internal error");
                }
            } else {
                throw yara::exception::Scan(
                    "scan_bytes() falied check if compiler rules sucessful use "
                    "load_rules()");
            }
        }

        void Yara::scan_fast_bytes(
            const std::string &p_buffer,
            const std::function<void(yara::record::Data *)> &p_callback) const
        {
            if (p_callback) {
                struct yara::record::Data *data = new struct yara::record::Data;

                data->match_status = yara::type::Scan::none;

                Yara::scan_bytes(p_buffer,
                                 reinterpret_cast<YR_CALLBACK_FUNC>(
                                     security::Yara::scan_fast_callback),
                                 data,
                                 SCAN_FLAGS_FAST_MODE);

                p_callback(data);

                delete data;
            }
        }

        YR_CALLBACK_FUNC
        Yara::scan_fast_callback(YR_SCAN_CONTEXT *p_context,
                                 const int p_message,
                                 void *p_message_data,
                                 void *p_user_data)
        {
            const YR_RULE *rule = reinterpret_cast<YR_RULE *>(p_message_data);
            yara::record::Data *user_data =
                static_cast<yara::record::Data *>(p_user_data);

            switch (p_message) {
                case CALLBACK_MSG_SCAN_FINISHED:
                    if (user_data->match_status == yara::type::Scan::none) {
                        user_data->match_status = yara::type::Scan::nomatch;
                        user_data->rule = "";
                        user_data->ns = "";
                    }
                    break;

                case CALLBACK_MSG_RULE_MATCHING:
                    user_data->ns = rule->ns->name;
                    user_data->rule = rule->identifier;
                    user_data->match_status = yara::type::Scan::match;
                    return (YR_CALLBACK_FUNC) CALLBACK_ABORT;

                case CALLBACK_MSG_RULE_NOT_MATCHING:
                    break;
            }

            return CALLBACK_CONTINUE;
        }

#ifdef ENGINE_PRO
        void Yara::_plugins()
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

            plugins::Plugins::lua.state.new_usertype<YR_NAMESPACE>(
                "Namespace",
                sol::constructors<YR_NAMESPACE()>(),
                "name",
                sol::readonly(&YR_NAMESPACE::name),
                "idx",
                sol::readonly(&YR_NAMESPACE::idx));

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

            plugins::Plugins::lua.state.new_usertype<YR_STREAM>(
                "Stream",
                sol::constructors<YR_STREAM()>(),
                "read",
                [](YR_STREAM &stream, sol::function func) {
                    static sol::function lua_read_func = func;
                    stream.read = [](void *ptr,
                                     size_t size,
                                     size_t count,
                                     void *) -> size_t {
                        if (!lua_read_func.valid()) {
                            return 0;
                        }
                        sol::protected_function_result result = lua_read_func(
                            std::string(static_cast<const char *>(ptr),
                                        size * count),
                            size,
                            count);
                        if (!result.valid()) {
                            sol::error err = result;
                            throw plugins::exception::Runtime(fmt::format(
                                "Lua callback error : {}", err.what()));
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
                            return 0;
                        }
                        sol::protected_function_result result = lua_write_func(
                            std::string(static_cast<const char *>(ptr),
                                        size * count),
                            size,
                            count);
                        if (!result.valid()) {
                            sol::error err = result;
                            throw plugins::exception::Runtime(fmt::format(
                                "Lua callback error in : {}\n", err.what()));
                            return 0;
                        }
                        return result;
                    };
                });

            plugins::Plugins::lua.state.new_usertype<yara::record::Data>(
                "Data",
                "match_status",
                sol::readonly(&yara::record::Data::match_status),
                "rule",
                sol::readonly(&yara::record::Data::rule),
                "ns",
                sol::readonly(&yara::record::Data::ns));

            plugins::Plugins::lua.state.new_usertype<engine::security::Yara>(
                "Yara",
                sol::constructors<engine::security::Yara()>(),
                "unload_stream_rules",
                Yara::unload_stream_rules,
                "load_stream_rules",
                Yara::load_stream_rules,
                "rules_foreach",
                &Yara::rules_foreach,
                "save_stream_rules",
                Yara::save_stream_rules,
                "load_compiler",
                Yara::load_compiler,
                "unload_compiler",
                Yara::unload_compiler,
                "load_rules_folder",
                &Yara::load_rules_folder,
                "load_rules",
                &Yara::load_rules,
                "scan_bytes",
                [](Yara &self,
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
                                case CALLBACK_MSG_RULE_MATCHING: {
                                    const YR_RULE *rule =
                                        reinterpret_cast<YR_RULE *>(
                                            message_data);
                                    result = scan_bytes_func(message, rule);
                                    break;
                                }
                                default:
                                    result = scan_bytes_func(message);
                                    break;
                            }
                            if (!result.valid()) {
                                sol::error err = result;
                                throw plugins::exception::Runtime(
                                    fmt::format("Lua callback error in : {}\n",
                                                err.what()));
                                return 0;
                            }
                            return result;
                        },
                        nullptr,
                        flags);
                },
                "scan_fast_bytes",
                &Yara::scan_fast_bytes,
                "rules_loaded_count",
                &Yara::rules_loaded_count,
                "load_rule_file",
                &Yara::load_rule_file,
                "load_rule_buff",
                &Yara::load_rule_buff);
        }
#endif
    }; // namespace security
} // namespace engine