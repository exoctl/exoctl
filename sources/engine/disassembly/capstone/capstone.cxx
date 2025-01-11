#include <alloca.h>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/memory/memory.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace engine
{
    namespace disassembly
    {
        Capstone::Capstone(cs_arch p_arch, cs_mode p_mode)
            : m_arch(p_arch), m_mode(p_mode)
        {
            if (cs_open(p_arch, p_mode, &m_handle) != CS_ERR_OK)
                throw capstone::exception::Initialize(
                    "Failed to initialize Capstone");
        }

        Capstone::~Capstone()
        {
            cs_close(&m_handle);
        }

        void Capstone::disassembly(
            const uint8_t *p_code,
            size_t p_code_size,
            const std::function<void(capstone::record::Data *p_data, size_t)>
                &p_callback)
        {
            if (!(IS_NULL(p_callback))) {

                capstone::record::Data *data = new capstone::record::Data;
                data->address = 0;

                const size_t count = cs_disasm(m_handle,
                                               p_code,
                                               p_code_size,
                                               data->address,
                                               0,
                                               &data->insn);

                if (count > 0) {
                    for (size_t i = 0; i < count; i++) {
                        p_callback(data, i);
                    }

                    cs_free(data->insn, count);
                }
                delete data;
            }
        }

        const cs_arch Capstone::get_arch()
        {
            return m_arch;
        }
        const cs_mode Capstone::get_mode()
        {
            return m_mode;
        }

        const std::string Capstone::arch_to_string(const cs_arch p_arch)
        {
            const auto arch = [](const cs_arch p_arch) -> std::string {
                switch (p_arch) {
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
                    case CS_ARCH_XCORE:
                        return "XCORE";
                    default:
                        return "";
                }
            }(p_arch);

            return arch;
        }

        const std::string Capstone::mode_to_string(const cs_mode p_mode)
        {
            const auto mode = [](const cs_mode p_mode) -> std::string {
                switch (p_mode) {
                    case CS_MODE_16:
                        return "16-bit";
                        break;
                    case CS_MODE_32:
                        return "32-bit";
                        break;
                    case CS_MODE_64:
                        return "64-bit";
                        break;
                    case CS_MODE_ARM:
                        return "ARM";
                        break;
                    case CS_MODE_THUMB:
                        return "Thumb";
                        break;
                    case CS_MODE_MIPS32R6:
                        return "MIPS32R6";
                        break;
                    default:
                        if ((p_mode & CS_MODE_16) == CS_MODE_16)
                            return "16-bit";
                        if ((p_mode & CS_MODE_32) == CS_MODE_32)
                            return "32-bit";
                        if ((p_mode & CS_MODE_64) == CS_MODE_64)
                            return "64-bit";
                        if ((p_mode & CS_MODE_ARM) == CS_MODE_ARM)
                            return "ARM";
                        if ((p_mode & CS_MODE_THUMB) == CS_MODE_THUMB)
                            return "Thumb";
                        if ((p_mode & CS_MODE_MIPS32R6) == CS_MODE_MIPS32R6)
                            return "MIPS32R6";
                        break;
                }

                return "";
            }(p_mode);

            return mode;
        }
    } // namespace disassembly
} // namespace engine