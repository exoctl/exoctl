#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/security/yara/yara.hxx>
#include <fcntl.h>
#include <fmt/core.h>
#include <sys/types.h>
#include <algorithm>
#include <unistd.h>
#include <mutex>

namespace engine
{
    namespace security
    {
        Yara::Yara() : m_yara_compiler(nullptr), m_yara_rules(nullptr)
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
            std::lock_guard<std::mutex> lock(m_compiler_mutex);
            return yr_compiler_create(&m_yara_compiler);
        }

        void Yara::unload_compiler()
        {
            std::lock_guard<std::mutex> lock(m_compiler_mutex);
            if (!IS_NULL(m_yara_compiler)) {
                yr_compiler_destroy(m_yara_compiler);
                m_yara_compiler = nullptr;
            }
        }

        void Yara::unload_rules()
        {
            std::unique_lock<std::shared_mutex> lock(m_rules_mutex);
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
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            const YR_RULE *rule;
            yr_rules_foreach(m_yara_rules, rule)
            {
                execute_safely([&]() { p_callback(*rule); });
            }
        }

        void Yara::strings_foreach(
            YR_RULE *p_rule,
            const std::function<void(const YR_STRING &)> &p_callback)
        {
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            YR_STRING *string;
            yr_rule_strings_foreach(p_rule, string)
            {
                execute_safely([&]() { p_callback(*string); });
            }
        }

        void Yara::metas_foreach(
            YR_RULE *p_rule,
            const std::function<void(const YR_META &)> &p_callback)
        {
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            const YR_META *meta;
            yr_rule_metas_foreach(p_rule, meta)
            {
                execute_safely([&]() { p_callback(*meta); });
            }
        }

        void Yara::tags_foreach(
            YR_RULE *p_rule,
            const std::function<void(const char *)> &p_callback)
        {
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            const char *tag;
            yr_rule_tags_foreach(p_rule, tag)
            {
                execute_safely([&]() { p_callback(tag); });
            }
        }

        const int Yara::load_rules_file(const char *p_file)
        {
            std::unique_lock<std::shared_mutex> lock(m_rules_mutex);
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
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            return yr_rules_save(m_yara_rules, p_file);
        }

        const int Yara::load_rules_stream(YR_STREAM &p_stream)
        {
            std::unique_lock<std::shared_mutex> lock(m_rules_mutex);
            return yr_rules_load_stream(&p_stream, &m_yara_rules);
        }

        const int Yara::save_rules_stream(YR_STREAM &p_stream)
        {
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
            return yr_rules_save_stream(m_yara_rules, &p_stream);
        }

        Yara::~Yara()
        {
            std::unique_lock<std::shared_mutex> rules_lock(m_rules_mutex);
            std::lock_guard<std::mutex> compiler_lock(m_compiler_mutex);

            if (yr_finalize() != ERROR_SUCCESS) {
                yara::exception::Finalize("yr_finalize() error finalize yara");
            }

            if (!IS_NULL(m_yara_compiler)) {
                yr_compiler_destroy(m_yara_compiler);
            }

            if (!IS_NULL(m_yara_rules)) {
                yr_rules_destroy(m_yara_rules);
            }
        }

        const int Yara::set_rule_file(const std::string &p_path,
                                      const std::string &p_yrname,
                                      const std::string &p_yrns) const
        {
            std::lock_guard<std::mutex> lock(m_compiler_mutex);
            const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);
            if (rules_fd == -1) {
                return ERROR_INVALID_FILE;
            }

            const int error_success = yr_compiler_add_fd(
                m_yara_compiler, rules_fd, p_yrns.c_str(), p_yrname.c_str());

            close(rules_fd);
            return error_success;
        }

        const int Yara::set_rule_buff(const std::string &p_rule,
                                      const std::string &p_yrns) const
        {
            std::lock_guard<std::mutex> lock(m_compiler_mutex);
            return yr_compiler_add_string(
                m_yara_compiler, p_rule.c_str(), p_yrns.c_str());
        }

        void Yara::set_rules_folder(const std::string &p_path) const
        {
            static std::mutex fs_mutex;
            std::lock_guard<std::mutex> fs_lock(fs_mutex);

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
                        closedir(dir);
                        throw yara::exception::LoadRules(
                            "yara_set_signature_rule() failed to compile "
                            "rule " +
                            std::string(full_path));
                    }
                } else if (entry->d_type == DT_DIR) {
                    Yara::set_rules_folder(full_path);
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
            std::unique_lock<std::shared_mutex> rules_lock(m_rules_mutex);
            std::lock_guard<std::mutex> compiler_lock(m_compiler_mutex);

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
            std::shared_lock<std::shared_mutex> lock(m_rules_mutex);

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
    } // namespace security
} // namespace engine