#include "syara.hxx"

#include <stdexcept>
#include <sys/types.h>
#include <dirent.h>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <alloca.h>

namespace Analysis
{
    SYara::SYara()
    {
        if (yr_initialize() != ERROR_SUCCESS)
        {
            throw std::runtime_error("yr_initialize() error initialize yara");
        }

        const int yr_compiler = yr_compiler_create(&m_yara_compiler);

        if (yr_compiler != ERROR_SUCCESS && yr_compiler == ERROR_INSUFFICIENT_MEMORY)
        {
            throw std::runtime_error("yr_compiler_create() error create compiler yara");
        }
    }

    SYara::~SYara()
    {
        if (yr_finalize() != ERROR_SUCCESS)
        {
            std::runtime_error("yr_finalize() error finalize yara");
        }

        if (m_yara_compiler != nullptr)
            yr_compiler_destroy(m_yara_compiler);

        if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS)
        {
            std::runtime_error("yr_rules_destroy() failed destroy rules");
        }
    }

    const int SYara::syara_set_signature_rule_fd(const std::string &p_path, const std::string &p_yrname) const
    {
        const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);

        const int error_success = yr_compiler_add_fd(m_yara_compiler, rules_fd, nullptr, p_yrname.c_str());

        close(rules_fd);

        return error_success;
    }

    const int SYara::syara_set_signature_rule_mem(const std::string &p_rule) const
    {
        return yr_compiler_add_string(m_yara_compiler, p_rule.c_str(), nullptr);
    }

    const void SYara::syara_load_rules_folder(const std::string &p_path) const
    {
        DIR *dir = opendir(p_path.c_str());
        if (!dir)
            throw std::runtime_error(strerror(errno));

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            const std::filesystem::path entry_name = entry->d_name;
            const std::string full_path = std::string(p_path) + "/" + entry_name.c_str();

            if (entry_name == "." || entry_name == "..")
                continue;

            if (entry_name.extension() == ".yar")
            {
                if (SYara::syara_set_signature_rule_fd(full_path, entry_name) != ERROR_SUCCESS)
                    throw std::runtime_error("syara_set_signature_rule() failed to compile rule " + std::string(full_path));
            }
            else if (entry->d_type == DT_DIR)
                syara_load_rules_folder(full_path);
        }

        closedir(dir);
    }

    const void SYara::load_rules(const std::function<void(void *)> &p_callback) const
    {
        p_callback(nullptr);
        SYara::syara_compiler_rules();
    }

    const void SYara::syara_compiler_rules() const
    {
        const int compiler_rules = yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
        if (compiler_rules != ERROR_SUCCESS ||
            compiler_rules == ERROR_INSUFFICIENT_MEMORY)
        {
            throw std::runtime_error("yr_compiler_get_rules() falied compiler rules " + compiler_rules);
        }
    }

    const stype SYara::scan_bytes(const std::string p_buffer, const std::function<void(void *)> &p_callback) const
    {
        struct yr_user_data *data = static_cast<struct yr_user_data *>(alloca(sizeof(struct yr_user_data)));

        data->is_malicius = benign;
        data->rule = nullptr;

        yr_rules_scan_mem(m_yara_rules, reinterpret_cast<const uint8_t *>(p_buffer.c_str()),
                          p_buffer.size(), SCAN_FLAGS_FAST_MODE,
                          reinterpret_cast<YR_CALLBACK_FUNC>(Analysis::SYara::syara_scan_callback_default),
                          data, 0);

        p_callback(data);

        const stype is_malicius = data->is_malicius;

        return is_malicius;
    }

    YR_CALLBACK_FUNC SYara::syara_scan_callback_default(YR_SCAN_CONTEXT *p_context,
                                                        int p_message,
                                                        void *p_message_data,
                                                        void *p_user_data)
    {
        YR_RULE *rule = reinterpret_cast<YR_RULE *>(p_message_data);

        switch (p_message)
        {
            case CALLBACK_MSG_SCAN_FINISHED:
                break;
            case CALLBACK_MSG_RULE_MATCHING:
                ((yr_user_data *)p_user_data)->rule = rule->identifier;
                ((yr_user_data *)p_user_data)->is_malicius = malicious;
                return (YR_CALLBACK_FUNC)CALLBACK_ABORT;

            case CALLBACK_MSG_RULE_NOT_MATCHING:
                break;
        }

        return CALLBACK_CONTINUE;
    }
};