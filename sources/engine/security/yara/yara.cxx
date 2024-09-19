#include <alloca.h>
#include <dirent.h>
#include <engine/security/yara/yara.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <fcntl.h>
#include <fmt/core.h>
#include <sys/types.h>
#include <unistd.h>

namespace Security
{
    Yara::Yara()
        : m_yara_compiler(nullptr), m_yara_rules(nullptr),
          m_rules_loaded_count(0)
    {
        if (yr_initialize() != ERROR_SUCCESS) {
            throw YaraException::Initialize(
                "yr_initialize() error initialize yara");
        }

        const int yr_compiler = yr_compiler_create(&m_yara_compiler);

        if (yr_compiler != ERROR_SUCCESS &&
            yr_compiler == ERROR_INSUFFICIENT_MEMORY) {
            throw YaraException::Initialize(
                "yr_compiler_create() error initialize compiler yara");
        }
    }

    Yara::~Yara()
    {
        if (yr_finalize() != ERROR_SUCCESS) {
            YaraException::Finalize("yr_finalize() error finalize yara");
        }

        if (m_yara_compiler != nullptr)
            yr_compiler_destroy(m_yara_compiler);

        if (m_yara_rules != nullptr) {
            if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS) {
                YaraException::Finalize(
                    "yr_rules_destroy() failed destroy rules");
            }
        }
    }

    const int Yara::yara_set_signature_rule_fd(const std::string &p_path,
                                               const std::string &p_yrname,
                                               const std::string &p_yrns) const
    {
        const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);

        const int error_success = yr_compiler_add_fd(
            m_yara_compiler, rules_fd, p_yrns.c_str(), p_yrname.c_str());

        close(rules_fd);

        m_rules_loaded_count++;
        return error_success;
    }

    const int Yara::yara_set_signature_rule_mem(const std::string &p_rule,
                                                const std::string &p_yrns) const
    {
        m_rules_loaded_count++;
        return yr_compiler_add_string(
            m_yara_compiler, p_rule.c_str(), p_yrns.c_str());
    }

    void Yara::yara_load_rules_folder(const std::filesystem::path &p_path) const
    {
        const std::string folder = p_path.filename();

        DIR *dir = opendir(p_path.c_str());
        if (!dir)
            throw YaraException::LoadRules(strerror(errno));

        const struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            const std::filesystem::path entry_name = entry->d_name;
            const std::string full_path =
                fmt::format("{}/{}", p_path.c_str(), entry_name.c_str());

            if (entry_name == "." || entry_name == "..") {
                continue;
            }
            if (entry_name.extension() == ".yar") {
                if (Yara::yara_set_signature_rule_fd(
                        full_path, entry_name, folder) != ERROR_SUCCESS) {
                    throw YaraException::LoadRules(
                        "yara_set_signature_rule() failed to compile rule " +
                        std::string(full_path));
                }
            } else if (entry->d_type == DT_DIR) {
                yara_load_rules_folder(full_path);
            }
        }

        closedir(dir);
    }

    void Yara::yara_load_rules(
        const std::function<void(void *)> &p_callback) const
    {
        p_callback((void *) m_rules_loaded_count);
        Yara::yara_compiler_rules();
    }

    void Yara::yara_compiler_rules() const
    {
        const int compiler_rules =
            yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
        if (compiler_rules != ERROR_SUCCESS ||
            compiler_rules == ERROR_INSUFFICIENT_MEMORY) {
            throw YaraException::CompilerRules(
                "yr_compiler_get_rules() falied compiler rules " +
                compiler_rules);
        }
    }

    void Yara::yara_scan_bytes(const std::string p_buffer,
                               YR_CALLBACK_FUNC p_callback,
                               void *p_data,
                               int p_flags) const
    {
        if (yr_rules_scan_mem(
                m_yara_rules,
                reinterpret_cast<const uint8_t *>(p_buffer.c_str()),
                p_buffer.size(),
                p_flags,
                p_callback,
                p_data,
                0) == ERROR_INTERNAL_FATAL_ERROR) {
            throw YaraException::Scan(
                "yr_rules_scan_mem() falied scan buffer, internal error");
        }
    }

    void Yara::yara_scan_fast_bytes(
        const std::string p_buffer,
        const std::function<void(Structs::Data *)> &p_callback) const
    {
        struct Structs::Data *data = static_cast<struct Structs::Data *>(
            alloca(sizeof(struct Structs::Data)));

        data->yara_match_status = Types::Scan::yara_none;

        Yara::yara_scan_bytes(p_buffer,
                              reinterpret_cast<YR_CALLBACK_FUNC>(
                                  Security::Yara::yara_scan_fast_callback),
                              data,
                              SCAN_FLAGS_FAST_MODE);

        p_callback(data);
    }

    YR_CALLBACK_FUNC
    Yara::yara_scan_fast_callback(YR_SCAN_CONTEXT *p_context,
                                  const int p_message,
                                  void *p_message_data,
                                  void *p_user_data)
    {
        const YR_RULE *rule = reinterpret_cast<YR_RULE *>(p_message_data);
        Structs::Data *user_data = static_cast<Structs::Data *>(p_user_data);

        switch (p_message) {
            case CALLBACK_MSG_SCAN_FINISHED:
                if (user_data->yara_match_status == Types::Scan::yara_none) {
                    user_data->yara_match_status = Types::Scan::yara_nomatch;
                    user_data->yara_rule = "";
                    user_data->yara_namespace = "";
                }
                break;

            case CALLBACK_MSG_RULE_MATCHING:
                user_data->yara_namespace = rule->ns->name;
                user_data->yara_rule = rule->identifier;
                user_data->yara_match_status = Types::Scan::yara_match;
                return (YR_CALLBACK_FUNC) CALLBACK_ABORT;

            case CALLBACK_MSG_RULE_NOT_MATCHING:
                break;
        }

        return CALLBACK_CONTINUE;
    }

    const uint64_t Yara::get_rules_loaded_count() const
    {
        return m_rules_loaded_count;
    }
}; // namespace Security