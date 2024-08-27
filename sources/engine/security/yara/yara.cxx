#include <alloca.h>
#include <dirent.h>
#include <engine/security/yara/yara.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <sys/types.h>
#include <unistd.h>

namespace Security
{
Yara::Yara() : m_rules_loaded_count(0)
{
    if (yr_initialize() != ERROR_SUCCESS)
    {
        throw YaraException::InitializeRules(
            "yr_initialize() error initialize yara");
    }

    const int yr_compiler = yr_compiler_create(&m_yara_compiler);

    if (yr_compiler != ERROR_SUCCESS &&
        yr_compiler == ERROR_INSUFFICIENT_MEMORY)
    {
        throw YaraException::InitializeRules(
            "yr_compiler_create() error create compiler yara");
    }
}

Yara::~Yara()
{
    if (yr_finalize() != ERROR_SUCCESS)
    {
        YaraException::FinalizeRules("yr_finalize() error finalize yara");
    }

    if (m_yara_compiler != nullptr)
        yr_compiler_destroy(m_yara_compiler);

    if (yr_rules_destroy(m_yara_rules) != ERROR_SUCCESS)
    {
        YaraException::FinalizeRules("yr_rules_destroy() failed destroy rules");
    }
}

const int Yara::yara_set_signature_rule_fd(const std::string &p_path,
                                           const std::string &p_yrname) const
{
    const YR_FILE_DESCRIPTOR rules_fd = open(p_path.c_str(), O_RDONLY);

    const int error_success = yr_compiler_add_fd(
        m_yara_compiler, rules_fd, nullptr, p_yrname.c_str());

    close(rules_fd);

    m_rules_loaded_count++;
    return error_success;
}

const int Yara::yara_set_signature_rule_mem(const std::string &p_rule) const
{
    m_rules_loaded_count++;
    return yr_compiler_add_string(m_yara_compiler, p_rule.c_str(), nullptr);
}

const void Yara::yara_load_rules_folder(const std::string &p_path) const
{
    DIR *dir = opendir(p_path.c_str());
    if (!dir)
        throw YaraException::LoadRules(strerror(errno));

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        const std::filesystem::path entry_name = entry->d_name;
        const std::string full_path =
            std::string(p_path) + "/" + entry_name.c_str();

        if (entry_name == "." || entry_name == "..")
            continue;

        if (entry_name.extension() == ".yar")
        {
            if (Yara::yara_set_signature_rule_fd(full_path, entry_name) !=
                ERROR_SUCCESS)
                throw YaraException::LoadRules(
                    "yara_set_signature_rule() failed to compile rule " +
                    std::string(full_path));
        }
        else if (entry->d_type == DT_DIR)
            yara_load_rules_folder(full_path);
    }

    closedir(dir);
}

const void
Yara::yara_load_rules(const std::function<void(void *)> &p_callback) const
{
    p_callback((void *) m_rules_loaded_count);
    Yara::yara_compiler_rules();
}

const void Yara::yara_compiler_rules() const
{
    const int compiler_rules =
        yr_compiler_get_rules(m_yara_compiler, &m_yara_rules);
    if (compiler_rules != ERROR_SUCCESS ||
        compiler_rules == ERROR_INSUFFICIENT_MEMORY)
    {
        throw YaraException::CompilerRules(
            "yr_compiler_get_rules() falied compiler rules " + compiler_rules);
    }
}

const void
Yara::yara_scan_bytes(const std::string p_buffer,
                      const std::function<void(void *)> &p_callback) const
{
    struct yr_user_data *data =
        static_cast<struct yr_user_data *>(alloca(sizeof(struct yr_user_data)));

    data->is_malicius = Types::YaraScan_t::none;
    data->yara_rule = nullptr;

    yr_rules_scan_mem(m_yara_rules,
                      reinterpret_cast<const uint8_t *>(p_buffer.c_str()),
                      p_buffer.size(),
                      SCAN_FLAGS_FAST_MODE,
                      reinterpret_cast<YR_CALLBACK_FUNC>(
                          Security::Yara::yara_scan_callback_default),
                      data,
                      0);

    p_callback(data);
}

YR_CALLBACK_FUNC Yara::yara_scan_callback_default(YR_SCAN_CONTEXT *p_context,
                                                  const int p_message,
                                                  void *p_message_data,
                                                  void *p_user_data)
{
    YR_RULE *rule = reinterpret_cast<YR_RULE *>(p_message_data);

    switch (p_message)
    {
    case CALLBACK_MSG_SCAN_FINISHED:
        break;
    case CALLBACK_MSG_RULE_MATCHING:
        ((yr_user_data *) p_user_data)->yara_rule = rule->identifier;
        ((yr_user_data *) p_user_data)->is_malicius =
            Types::YaraScan_t::malicious;
        return (YR_CALLBACK_FUNC) CALLBACK_ABORT;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        ((yr_user_data *) p_user_data)->is_malicius = Types::YaraScan_t::benign;
        break;
    }

    return CALLBACK_CONTINUE;
}

const uint64_t Yara::get_rules_loaded_count() const
{
    return m_rules_loaded_count;
}
}; // namespace Security