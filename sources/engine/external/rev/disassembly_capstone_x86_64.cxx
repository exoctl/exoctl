#include <engine/external/rev/disassembly_capstone_x86_64.hxx>
#include <fmt/core.h>

namespace Rev
{
CapstoneX86::CapstoneX86() : m_capstone(CS_ARCH_X86, CS_MODE_64)
{
    dto_set_field("address", 0);
    dto_set_field("mnemonic", "none");
    dto_set_field("bytes", "none");
    dto_set_field("operands", "none");
    dto_set_field("comments", "none");
}
CapstoneX86::~CapstoneX86() {}

void CapstoneX86::capstonex86_disassembly(const std::string &p_code)
{
    m_capstone.capstone_disassembly(
        reinterpret_cast<const uint8_t *>(p_code.data()),
        p_code.size(),
        [&](struct Disassembly::cs_user_data *p_user_data, size_t p_count)
        {
            fmt::print("{:x} {} {}\n",
                       p_user_data->insn[p_count].address,
                       p_user_data->insn[p_count].mnemonic,
                       p_user_data->insn[p_count].op_str);
        });
}
} // namespace Rev