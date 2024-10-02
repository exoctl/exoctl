#include <disassembly/capstone/capstone.hxx>
#include <engine/disassembly/capstone/capstone_exception.hxx>

TEST_F(CapstoneTest, CapstoneDisassembly)
{
    const std::string opcode = "\xc3";
    EXPECT_NO_THROW(capstone->capstone_disassembly(
        reinterpret_cast<const uint8_t *>(opcode.data()),
        opcode.size(),
        [&](const Disassembly::Struct::Data *p_data, size_t index) {
            ASSERT_EQ("ret", std::string(p_data->insn[index].mnemonic));
            ASSERT_EQ(1, p_data->insn[index].size);
            ASSERT_GE(p_data->insn[index].address, 0x0);
        }));
}

TEST_F(CapstoneTest, CapstoneGetArch)
{
    ASSERT_EQ(capstone->capstone_get_arch(), CS_ARCH_X86);
}

TEST_F(CapstoneTest, CapstoneGetMode)
{
    ASSERT_EQ(capstone->capstone_get_mode(), CS_MODE_64);
}

TEST_F(CapstoneTest, CapstoneArchToString)
{
    EXPECT_EQ(capstone->capstone_arch_to_string(CS_ARCH_X86), "x86");
}

TEST_F(CapstoneTest, CapstoneModeToString)
{
    EXPECT_EQ(capstone->capstone_mode_to_string(CS_MODE_64), "64-bit");
}
