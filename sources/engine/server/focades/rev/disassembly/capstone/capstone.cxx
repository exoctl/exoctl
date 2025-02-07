#include <engine/memory/memory.hxx>
#include <engine/server/focades/rev/disassembly/capstone/capstone.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdint.h>
#include <vector>

namespace engine
{
    namespace focades
    {
        namespace rev
        {
            namespace disassembly
            {
                Capstone::Capstone(const cs_arch p_arch, const cs_mode p_mode)
                    : m_capstone(p_arch, p_mode),
                      m_arch(m_capstone.arch_to_string(p_arch)),
                      m_mode(m_capstone.mode_to_string(p_mode))
                {
                }

                void Capstone::disassembly(
                    const std::string &p_code,
                    const std::function<void(capstone::record::DTO *)>
                        &p_callback)
                {
                    if (!IS_NULL(p_callback)) {
                        struct capstone::record::DTO *dto =
                            new capstone::record::DTO;

                        dto->arch = m_arch;
                        dto->mode = m_mode;

                        m_capstone.disassembly(
                            reinterpret_cast<const uint8_t *>(p_code.data()),
                            p_code.size(),
                            [&](struct ::engine::disassembly::capstone::record::
                                    Data *p_user_data,
                                size_t p_count) {
                                capstone::record::Instruction instruction;
                                auto &insn = p_user_data->insn[p_count];

                                instruction.address =
                                    fmt::format("0x{:x}", insn.address);
                                instruction.mnemonic = insn.mnemonic;
                                instruction.operands = insn.op_str;
                                instruction.size = insn.size;
                                instruction.id = insn.id;
                                instruction.bytes = fmt::format(
                                    "{:x}",
                                    fmt::join(insn.bytes,
                                              insn.bytes + insn.size,
                                              " "));

                                dto->instructions.push_back(instruction);
                            });

                        p_callback(dto);
                        delete dto;
                    }
                }

                parser::Json Capstone::dto_json(
                    const capstone::record::DTO *p_dto)
                {
                    parser::Json disassembly;

                    if (!IS_NULL(p_dto)) {
                        std::vector<parser::Json> ins;

                        disassembly.add_member_string("arch", m_arch);
                        disassembly.add_member_string("mode", m_mode);

                        for (const auto &instruction : p_dto->instructions) {
                            parser::Json ins_json;
                            ins_json.add_member_string("address",
                                                       instruction.address);
                            ins_json.add_member_string("mnemonic",
                                                       instruction.mnemonic);
                            ins_json.add_member_string("operands",
                                                       instruction.operands);
                            ins_json.add_member_uint16("size",
                                                       instruction.size);
                            ins_json.add_member_int("id", instruction.id);
                            ins_json.add_member_string("bytes",
                                                       instruction.bytes);

                            ins.push_back(ins_json);
                        }

                        disassembly.add_member_vector("instructions", ins);
                    }

                    return disassembly;
                }
            } // namespace disassembly
        } // namespace rev
    } // namespace focades
} // namespace engine