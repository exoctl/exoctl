#include <algorithm>
#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/security/yara/yara.hxx>
#include <fcntl.h>
#include <fmt/core.h>
#include <mutex>
#include <sys/types.h>
#include <unistd.h>

namespace engine
{
    namespace security
    {
        Yara::Yara() : yara_compiler_(nullptr), yara_rules_(nullptr)
        {
            if (yr_initialize() != ERROR_SUCCESS) {
                throw yara::exception::Initialize(
                    "yr_initialize() error initialize yara");
            }

            const int yr_compiler = Yara::load_compiler();
            if (yr_compiler != ERROR_SUCCESS) {
                throw yara::exception::Initialize(
                    "yr_compiler_create() error initialize compiler yara");
            }
        }

        const int Yara::load_compiler()
        {
            std::lock_guard<std::mutex> lock(compiler_mutex_);
            return yr_compiler_create(&yara_compiler_);
        }

        void Yara::unload_compiler()
        {
            std::lock_guard<std::mutex> lock(compiler_mutex_);
            if (!IS_NULL(yara_compiler_)) {
                yr_compiler_destroy(yara_compiler_);
                yara_compiler_ = nullptr;
            }
        }

        void Yara::unload_rules()
        {
            std::unique_lock<std::shared_mutex> lock(rules_mutex_);
            if (!IS_NULL(yara_rules_)) {
                if (yr_rules_destroy(yara_rules_) != ERROR_SUCCESS) {
                    /* nothing */
                }
                yara_rules_ = nullptr;
            }
        }

        void Yara::rules_foreach(
            const std::function<void(const YR_RULE &)> &p_callback)
        {
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
            const YR_RULE *rule;
            yr_rules_foreach(yara_rules_, rule)
            {
                execute_safely([&]() { p_callback(*rule); });
            }
        }

        void Yara::strings_foreach(
            YR_RULE *p_rule,
            const std::function<void(const YR_STRING &)> &p_callback)
        {
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
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
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
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
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
            const char *tag;
            yr_rule_tags_foreach(p_rule, tag)
            {
                execute_safely([&]() { p_callback(tag); });
            }
        }

        const int Yara::load_rules_file(const char *p_file)
        {
            const std::unique_lock<std::shared_mutex> lock(rules_mutex_);
            return yr_rules_load(p_file, &yara_rules_);
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
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
            return yr_rules_save(yara_rules_, p_file);
        }

        const int Yara::load_rules_stream(YR_STREAM &p_stream)
        {
            const std::unique_lock<std::shared_mutex> lock(rules_mutex_);
            return yr_rules_load_stream(&p_stream, &yara_rules_);
        }

        const int Yara::save_rules_stream(YR_STREAM &p_stream)
        {
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
            return yr_rules_save_stream(yara_rules_, &p_stream);
        }

        Yara::~Yara()
        {
            const std::unique_lock<std::shared_mutex> rules_lock(rules_mutex_);
            const std::lock_guard<std::mutex> compiler_lock(compiler_mutex_);

            if (yr_finalize() != ERROR_SUCCESS) {
                yara::exception::Finalize("yr_finalize() error finalize yara");
            }

            if (!IS_NULL(yara_compiler_)) {
                yr_compiler_destroy(yara_compiler_);
            }

            if (!IS_NULL(yara_rules_)) {
                yr_rules_destroy(yara_rules_);
            }
        }

        const int Yara::set_rule_file(const std::string &p_path,
                                      const std::string &p_yrname,
                                      const std::string &p_yrns) const
        {
            const std::lock_guard<std::mutex> lock(compiler_mutex_);
            const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);
            if (rules_fd == -1) {
                return ERROR_INVALID_FILE;
            }

            const int error_success = yr_compiler_add_fd(
                yara_compiler_, rules_fd, p_yrns.c_str(), p_yrname.c_str());

            close(rules_fd);
            return error_success;
        }

        const int Yara::set_rule_buff(const std::string &p_rule,
                                      const std::string &p_yrns) const
        {
            const std::lock_guard<std::mutex> lock(compiler_mutex_);
            return yr_compiler_add_string(
                yara_compiler_, p_rule.c_str(), p_yrns.c_str());
        }

        void Yara::set_rules_folder(const std::string &p_path) const
        {
            DIR *dir = opendir(p_path.c_str());
            if (!dir)
                throw yara::exception::LoadRules(
                    fmt::format("{} : '{}'", strerror(errno), p_path));

            const struct dirent *entry;
            while ((entry = readdir(dir)) != nullptr) {
                std::filesystem::path entry_name(entry->d_name);
                if (entry_name == "." || entry_name == "..")
                    continue;

                std::string full_path = p_path + "/" + entry_name.string();

                if (entry_name.extension() == ".yar") {
                    if (Yara::set_rule_file(full_path,
                                            entry_name,
                                            std::filesystem::path(p_path)
                                                .filename()
                                                .string()) != ERROR_SUCCESS) {
                        closedir(dir);
                        throw yara::exception::LoadRules(
                            "yara_set_signature_rule() failed to compile "
                            "rule " +
                            full_path);
                    }
                } else if (entry->d_type == DT_DIR) {
                    Yara::set_rules_folder(full_path);
                }
            }
            closedir(dir);
        }

        void Yara::load_rules() const
        {
            Yara::compiler_rules();
        }

        void Yara::compiler_rules() const
        {
            const std::unique_lock<std::shared_mutex> rules_lock(rules_mutex_);
            const std::lock_guard<std::mutex> compiler_lock(compiler_mutex_);

            const int compiler_rules =
                yr_compiler_get_rules(yara_compiler_, &yara_rules_);
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
                              yara::type::Flags p_flags) const
        {
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);

            if (yara_compiler_ != nullptr && yara_rules_ != nullptr) {
                if (yr_rules_scan_mem(
                        yara_rules_,
                        reinterpret_cast<const uint8_t *>(p_buffer.data()),
                        p_buffer.size(),
                        (int) p_flags,
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