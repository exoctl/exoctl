#include "syara.hxx"

#include <stdexcept>
#include <sys/types.h>
#include <dirent.h>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>

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
        YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);

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

    const void SYara::load_rules(const std::function<void(void*)> &p_callback) const
    {
        p_callback(nullptr);
        SYara::syara_compiler_rules();
    }

    const void SYara::syara_compiler_rules() const
    {
        int compiler_rules = yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
        if (compiler_rules != ERROR_SUCCESS ||
            compiler_rules == ERROR_INSUFFICIENT_MEMORY)
        {
            throw std::runtime_error("yr_compiler_get_rules() falied compiler rules " + compiler_rules);
        }
    }

    const stypes SYara::scan_bytes(const uint8_t *p_buffer, size_t p_size) const
    {
        yr_rules_scan_mem(m_yara_rules, p_buffer, p_size, SCAN_FLAGS_FAST_MODE, nullptr, nullptr, 0);
    }
};