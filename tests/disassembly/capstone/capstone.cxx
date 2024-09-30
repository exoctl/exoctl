#include <disassembly/capstone/capstone.hxx>

TEST_F(CapstoneTest, CapstoneDisassembly)
{
    EXPECT_NO_THROW(capstone->capstone_disassembly((const unsigned char *) "\xc3", 1, nullptr));
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
