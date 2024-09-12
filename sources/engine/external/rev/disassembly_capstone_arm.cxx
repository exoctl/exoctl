#include <engine/external/rev/disassembly_capstone_arm.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <vector>

namespace Rev
{
CapstoneARM::CapstoneARM() : m_capstone(CS_ARCH_ARM, CS_MODE_ARM)
{
    dto_set_field("arch", "ARM");
    dto_set_field("mode", "ARM");
}

CapstoneARM::~CapstoneARM() {}

void CapstoneARM::capstonearm_disassembly(const std::string &p_code)
{
    Parser::Json disassembly = Parser::Json::array();

    m_capstone.capstone_disassembly(
        reinterpret_cast<const uint8_t *>(p_code.data()),
        p_code.size(),
        [&](struct Disassembly::cs_user_data *p_user_data, size_t p_count)
        {
            Parser::Json instruction;
            auto &insn = p_user_data->insn[p_count];
            
            instruction["address"] = fmt::format("0x{:x}", insn.address);
            instruction["mnemonic"] = insn.mnemonic;
            instruction["operands"] = insn.op_str;
            instruction["size"] = insn.size;
            instruction["id"] = insn.id;
            instruction["bytes"] = fmt::format(
                "{:x}", fmt::join(insn.bytes, insn.bytes + insn.size, " "));

            disassembly.push_back(instruction);
        });

    dto_set_field("disassembly", disassembly);
}
} // namespace Rev