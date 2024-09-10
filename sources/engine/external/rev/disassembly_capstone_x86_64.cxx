#include <engine/external/rev/disassembly_capstone_x86_64.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <vector>

namespace Rev
{
CapstoneX86::CapstoneX86() : m_capstone(CS_ARCH_X86, CS_MODE_64)
{
    dto_set_field("arch", "x86_64");
    dto_set_field("mode", "64");
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
            instruction["address"] =
                fmt::format("{:x}", p_user_data->insn[p_count].address);
            instruction["mnemonic"] = p_user_data->insn[p_count].mnemonic;
            instruction["operands"] = p_user_data->insn[p_count].op_str;
            instruction["size"] = p_user_data->insn[p_count].size;
            for (size_t i = 0; i < p_user_data->insn[p_count].size; ++i)
            {
                instruction["bytes"] +=
                    fmt::format(" {:x}", p_user_data->insn[p_count].bytes[i]);
            }

            disassembly.push_back(instruction);
        });

    dto_set_field("disassembly", disassembly);
}
} // namespace Rev
