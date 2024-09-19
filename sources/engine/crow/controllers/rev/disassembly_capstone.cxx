#include <engine/crow/controllers/rev/disassembly_capstone.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace Controllers
{
    namespace Rev
    {
        Capstone::Capstone(const cs_arch p_arch, const cs_mode p_mode)
            : m_capstone(p_arch, p_mode)
        {
            dto_set_field("arch", m_capstone.capstone_arch_to_string(p_arch));
            dto_set_field("mode", m_capstone.capstone_mode_to_string(p_mode));
        }

        Capstone::~Capstone()
        {
        }

        void Capstone::capstone_disassembly(const std::string &p_code)
        {
            Parser::Json disassembly = Parser::Json::array();

            m_capstone.capstone_disassembly(
                reinterpret_cast<const uint8_t *>(p_code.data()),
                p_code.size(),
                [&](struct Disassembly::Struct::Data *p_user_data,
                    size_t p_count) {
                    Parser::Json instruction;
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

                    disassembly.push_back(instruction);
                });

            dto_set_field("disassembly", disassembly);
        }
    } // namespace Rev
} //  namespace Controllers