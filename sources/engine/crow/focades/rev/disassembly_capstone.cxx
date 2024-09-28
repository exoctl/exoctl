#include <engine/crow/focades/rev/disassembly_capstone.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdint.h>

namespace Focades
{
    namespace Rev
    {
        Capstone::Capstone(const cs_arch p_arch, const cs_mode p_mode)
            : m_capstone(p_arch, p_mode),
              m_arch(m_capstone.capstone_arch_to_string(p_arch)),
              m_mode(m_capstone.capstone_mode_to_string(p_mode))
        {
        }

        Capstone::~Capstone()
        {
        }

        void Capstone::capstone_disassembly(
            const std::string &p_code,
            const std::function<void(Structs::DTO *)> &p_callback)
        {
            struct Structs::DTO *dto = new Structs::DTO;

            dto->arch = m_arch;
            dto->mode = m_mode;

            m_capstone.capstone_disassembly(
                reinterpret_cast<const uint8_t *>(p_code.data()),
                p_code.size(),
                [&](struct Disassembly::Struct::Data *p_user_data,
                    size_t p_count) {
                    std::map<std::string, std::string> instruction;
                    auto &insn = p_user_data->insn[p_count];

                    instruction["address"] =
                        fmt::format("0x{:x}", insn.address);
                    instruction["mnemonic"] = insn.mnemonic;
                    instruction["operands"] = insn.op_str;
                    instruction["size"] = insn.size;
                    instruction["id"] = insn.id;
                    instruction["bytes"] = fmt::format(
                        "{:x}",
                        fmt::join(insn.bytes, insn.bytes + insn.size, " "));

                    //dto->instructions.push_back(instruction);
                });

            p_callback(dto);
            delete dto;
        }

        const Parser::Json Capstone::capstone_dto_json(
            const Structs::DTO *p_dto)
        {
            return Parser::Json{{{"arch", p_dto->arch}, {"mode", p_dto->mode}}};
        }
    } // namespace Rev
} // namespace Focades