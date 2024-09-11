#include <engine/external/rev/disassembly_capstone_x86_64.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <vector>

namespace Rev
{
CapstoneX86::CapstoneX86() : m_capstone(CS_ARCH_X86, CS_MODE_64)
{
    dto_set_field("arch", "x86_64");
    dto_set_field("mode", "x64");
}

CapstoneX86::~CapstoneX86() {}

void CapstoneX86::capstonex86_disassembly(const std::string &p_code)
{
    Parser::Json disassembly = Parser::Json::array();

    m_capstone.capstone_disassembly(
        reinterpret_cast<const uint8_t *>(p_code.data()),
        p_code.size(),
        [&](struct Disassembly::cs_user_data *p_user_data, size_t p_count)
        {
            Parser::Json instruction;
            auto &insn = p_user_data->insn[p_count];
            
            instruction["address"] = fmt::format("{:x}", insn.address);
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