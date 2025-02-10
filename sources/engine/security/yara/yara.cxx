#include <dirent.h>
#include <engine/memory/memory.hxx>
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

            const int yr_compiler = yr_compiler_create(&m_yara_compiler);

            if (yr_compiler != ERROR_SUCCESS &&
                yr_compiler == ERROR_INSUFFICIENT_MEMORY) {
                throw yara::exception::Initialize(
                    "yr_compiler_create() error initialize compiler yara");
            }
        }

        Yara::~Yara()
        {
            if (yr_finalize() != ERROR_SUCCESS) {
                yara::exception::Finalize("yr_finalize() error finalize yara");
            }

            if (!IS_NULL(m_yara_compiler))
                yr_compiler_destroy(m_yara_compiler);

            if (!IS_NULL(m_yara_rules)) {
                if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS) {
                    yara::exception::Finalize(
                        "yr_rules_destroy() failed destroy rules");
                }
            }
        }
#ifdef ENGINE_PRO
        void Yara::register_plugins()
        {
            plugins::Plugins::lua.state["_yara"] = this;

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
                "load_rules_folder",
                &engine::security::Yara::load_rules_folder,
                "load_rules",
                &engine::security::Yara::load_rules,
                "scan_bytes",
                &engine::security::Yara::scan_bytes,
                "scan_fast_bytes",
                engine::security::Yara::scan_fast_bytes,
                "rules_loaded_count",
                &engine::security::Yara::rules_loaded_count,
                "set_signature_rule_fd",
                &engine::security::Yara::set_signature_rule_fd,
                "set_signature_rule_mem",
                &engine::security::Yara::set_signature_rule_mem);
        }
#endif
        const int Yara::set_signature_rule_fd(const std::string &p_path,
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

        const int Yara::set_signature_rule_mem(const std::string &p_rule,
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

            const struct dirent *entry;
            while (!IS_NULL((entry = readdir(dir)))) {
                const std::filesystem::path entry_name = entry->d_name;
                const std::string full_path =
                    fmt::format("{}/{}", p_path.c_str(), entry_name.c_str());

                if (entry_name == "." || entry_name == "..") {
                    continue;
                }
                if (entry_name.extension() == ".yar") {
                    if (Yara::set_signature_rule_fd(
                            full_path, entry_name, p_path) != ERROR_SUCCESS) {
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

        void Yara::scan_bytes(const std::string p_buffer,
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
            const std::string p_buffer,
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
    }; // namespace security
} // namespace engine