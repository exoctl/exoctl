#include <engine/crowapp/focades/rev/disassembly/capstone/capstone.hxx>
#include <engine/memory.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdint.h>
#include <vector>

namespace focades
{
    namespace rev
    {
        namespace disassembly
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
                const std::function<void(capstone::record::DTO *)> &p_callback)
            {
                if (!IS_NULL(p_callback)) {
                    struct capstone::record::DTO *dto =
                        new capstone::record::DTO;

                    dto->capstone_arch = m_arch;
                    dto->capstone_mode = m_mode;

                    m_capstone.capstone_disassembly(
                        reinterpret_cast<const uint8_t *>(p_code.data()),
                        p_code.size(),
                        [&](struct ::disassembly::capstone::record::Data
                                *p_user_data,
                            size_t p_count) {
                            capstone::record::Instruction instruction;
                            auto &insn = p_user_data->capstone_insn[p_count];

                            instruction.capstone_address =
                                fmt::format("0x{:x}", insn.address);
                            instruction.capstone_mnemonic = insn.mnemonic;
                            instruction.capstone_operands = insn.op_str;
                            instruction.capstone_size = insn.size;
                            instruction.capstone_id = insn.id;
                            instruction.capstone_bytes = fmt::format(
                                "{:x}",
                                fmt::join(
                                    insn.bytes, insn.bytes + insn.size, " "));

                            dto->capstone_instructions.push_back(instruction);
                        });

                    p_callback(dto);
                    delete dto;
                }
            }

            parser::Json Capstone::capstone_dto_json(
                const capstone::record::DTO *p_dto)
            {
                parser::Json disassembly;

                if (!IS_NULL(p_dto)) {
                    std::vector<parser::Json> ins;

                    disassembly.json_add_member_string("arch", m_arch);
                    disassembly.json_add_member_string("mode", m_mode);

                    for (const auto &instruction :
                         p_dto->capstone_instructions) {
                        parser::Json ins_json;
                        ins_json.json_add_member_string(
                            "address", instruction.capstone_address);
                        ins_json.json_add_member_string(
                            "mnemonic", instruction.capstone_mnemonic);
                        ins_json.json_add_member_string(
                            "operands", instruction.capstone_operands);
                        ins_json.json_add_member_uint16(
                            "size", instruction.capstone_size);
                        ins_json.json_add_member_int("id",
                                                     instruction.capstone_id);
                        ins_json.json_add_member_string(
                            "bytes", instruction.capstone_bytes);

                        ins.push_back(ins_json);
                    }

                    disassembly.json_add_member_vector("instructions", ins);
                }

                return disassembly;
            }
        } // namespace disassembly
    } // namespace rev
} // namespace focades