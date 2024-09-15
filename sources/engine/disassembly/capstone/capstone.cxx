#include <alloca.h>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/disassembly/capstone/capstone_exception.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace Disassembly
{

Capstone::Capstone(cs_arch p_arch, cs_mode p_mode)
    : m_arch(p_arch), m_mode(p_mode)
{
    if (cs_open(p_arch, p_mode, &m_handle) != CS_ERR_OK)
        throw CapstoneException::Initialize("Failed to initialize Capstone");
}

Capstone::~Capstone() { cs_close(&m_handle); }

void Capstone::capstone_disassembly(
    const uint8_t *p_code,
    size_t p_code_size,
    const std::function<void(struct cs_user_data *p_user_data, size_t)>
        &p_callback)
{
    struct cs_user_data *user_data =
        static_cast<struct cs_user_data *>(alloca(sizeof(struct cs_user_data)));

    const size_t count = cs_disasm(
        m_handle, p_code, p_code_size, user_data->address, 0, &user_data->insn);

    if (count > 0)
    {
        if (p_callback)
        {
            for (size_t i = 0; i < count; i++)
                p_callback(user_data, i);
        }

        cs_free(user_data->insn, count);
    }
    else
    {
        const cs_err err = cs_errno(m_handle);
        if (err != CS_ERR_OK)
        {
            throw CapstoneException::FailedDisassembly(
                fmt::format("Disassembly failed: {}, address: {:#x}, code: {}",
                            cs_strerror(err),
                            user_data->address,
                            fmt::join(p_code, p_code + p_code_size, " ")));
        }
    }
}

const cs_arch Capstone::capstone_get_arch() { return m_arch; }
const cs_mode Capstone::capstone_get_mode() { return m_mode; }

const std::string Capstone::capstone_arch_to_string(const cs_arch p_arch)
{
    switch (p_arch)
    {
    case CS_ARCH_X86:
        return "x86";
    case CS_ARCH_ARM:
        return "ARM";
    case CS_ARCH_ARM64:
        return "ARM64";
    case CS_ARCH_MIPS:
        return "MIPS";
    case CS_ARCH_PPC:
        return "PPC";
    case CS_ARCH_SPARC:
        return "SPARC";
    case CS_ARCH_SYSZ:
        return "SYSZ";
    case CS_ARCH_XCORE:
        return "XCORE";
    default:
        return "none";
    }

    return "none";
}

const std::string Capstone::capstone_mode_to_string(const cs_mode p_mode)
{
    std::string result;

    switch (p_mode)
    {
    case CS_MODE_16:
        result += "16-bit";
        break;
    case CS_MODE_32:
        result += "32-bit";
        break;
    case CS_MODE_64:
        result += "64-bit";
        break;
    case CS_MODE_ARM:
        result += "ARM";
        break;
    case CS_MODE_THUMB:
        result += "Thumb";
        break;
    case CS_MODE_MIPS32R6:
        result += "MIPS32R6";
        break;
    default:
        if ((p_mode & CS_MODE_16) == CS_MODE_16)
            result += "16-bit";
        if ((p_mode & CS_MODE_32) == CS_MODE_32)
            result += "32-bit";
        if ((p_mode & CS_MODE_64) == CS_MODE_64)
            result += "64-bit";
        if ((p_mode & CS_MODE_ARM) == CS_MODE_ARM)
            result += "ARM";
        if ((p_mode & CS_MODE_THUMB) == CS_MODE_THUMB)
            result += "Thumb";
        if ((p_mode & CS_MODE_MIPS32R6) == CS_MODE_MIPS32R6)
            result += "MIPS32R6";
        break;
    }

    return result.empty() ? "none" : result;
}
} // namespace Disassembly