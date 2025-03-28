#include <dirent.h>
#include <engine/memory/memory.hxx>
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

        void Yara::unload_rules()
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

        void Yara::strings_foreach(
            YR_RULE *p_rule,
            const std::function<void(const YR_STRING &)> &p_callback)
        {
            YR_STRING *string;
            yr_rule_strings_foreach(p_rule, string)
            {
                p_callback(*string);
            }
        }

        void Yara::metas_foreach(
            YR_RULE *p_rule,
            const std::function<void(const YR_META &)> &p_callback)
        {
            const YR_META *meta;
            yr_rule_metas_foreach(p_rule, meta)
            {
                p_callback(*meta);
            }
        }

        void Yara::tags_foreach(
            YR_RULE *p_rule,
            const std::function<void(const char *)> &p_callback)
        {
            const char *tag;

            yr_rule_tags_foreach(p_rule, tag)
            {
                p_callback(tag);
            }
        }

        const int Yara::load_rules_file(const char *p_file)
        {
            return yr_rules_load(p_file, &m_yara_rules);
        }

        void Yara::rule_disable(YR_RULE &p_rule)
        {
            yr_rule_disable(&p_rule);
        }

        void Yara::rule_enable(YR_RULE &p_rule)
        {
            yr_rule_enable(&p_rule);
        }

        const int Yara::save_rules_file(const char *p_file)
        {
            return yr_rules_save(m_yara_rules, p_file);
        }

        const int Yara::load_rules_stream(YR_STREAM &p_stream)
        {
            return yr_rules_load_stream(&p_stream, &m_yara_rules);
        }

        const int Yara::save_rules_stream(YR_STREAM &p_stream)
        {
            return yr_rules_save_stream(m_yara_rules, &p_stream);
        }

        Yara::~Yara()
        {
            if (yr_finalize() != ERROR_SUCCESS) {
                yara::exception::Finalize("yr_finalize() error finalize yara");
            }

            Yara::unload_compiler();
            Yara::unload_rules();
        }

        const int Yara::set_rule_file(const std::string &p_path,
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

        const int Yara::set_rule_buff(const std::string &p_rule,
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
                    if (Yara::set_rule_file(full_path,
                                            entry_name,
                                            replace_slashes_with_dots(
                                                p_path)) != ERROR_SUCCESS) {
                        throw yara::exception::LoadRules(
                            "yara_set_signature_rule() failed to compile "
                            "rule " +
                            std::string(full_path));
                    }
                } else if (entry->d_type == DT_DIR) {
                    Yara::load_rules_folder(full_path);
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
    }; // namespace security
} // namespace engine