#include <engine/crow/focades/rev/disassembly/capstone.hxx>
#include <engine/memory.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdint.h>
#include <vector>

namespace Focades
{
    namespace Rev
    {
        namespace Disassembly
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
                if (!IS_NULL(p_callback)) {
                    struct Structs::DTO *dto = new Structs::DTO;

                    dto->arch = m_arch;
                    dto->mode = m_mode;

                    m_capstone.capstone_disassembly(
                        reinterpret_cast<const uint8_t *>(p_code.data()),
                        p_code.size(),
                        [&](struct ::Disassembly::Struct::Data *p_user_data,
                            size_t p_count) {
                            Structs::Instruction instruction;
                            auto &insn = p_user_data->insn[p_count];

                            instruction.address =
                                fmt::format("0x{:x}", insn.address);
                            instruction.mnemonic = insn.mnemonic;
                            instruction.operands = insn.op_str;
                            instruction.size = insn.size;
                            instruction.id = insn.id;
                            instruction.bytes = fmt::format(
                                "{:x}",
                                fmt::join(
                                    insn.bytes, insn.bytes + insn.size, " "));

                            dto->instructions.push_back(instruction);
                        });

                    p_callback(dto);
                    delete dto;
                }
            }

            ::Parser::Json Capstone::capstone_dto_json(
                const Structs::DTO *p_dto)
            {
                Parser::Json disassembly;
                
                if (!IS_NULL(p_dto)) {
                    std::vector<Parser::Json> ins;

                    disassembly.json_add_member_string("arch", m_arch);
                    disassembly.json_add_member_string("mode", m_mode);

                    for (const auto &instruction : p_dto->instructions) {
                        Parser::Json ins_json;
                        ins_json.json_add_member_string("address",
                                                        instruction.address);
                        ins_json.json_add_member_string("mnemonic",
                                                        instruction.mnemonic);
                        ins_json.json_add_member_string("operands",
                                                        instruction.operands);
                        ins_json.json_add_member_uint16("size",
                                                        instruction.size);
                        ins_json.json_add_member_int("id", instruction.id);
                        ins_json.json_add_member_string("bytes",
                                                        instruction.bytes);

                        ins.push_back(ins_json);
                    }

                    disassembly.json_add_member_vector("instructions", ins);
                }

                return disassembly;
            }
        } // namespace Disassembly
    } // namespace Rev
} // namespace Focades