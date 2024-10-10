#include <parser/toml.hxx>

TEST_F(TomlTest, TomlGetTblString)
{
    std::string tbl_string =
        toml->get_tbl()["project"]["name"].value<std::string>().value();
    EXPECT_EQ("Engine", tbl_string);
}

TEST_F(TomlTest, TomlGetTblUint16)
{
    std::uint16_t test_short =
        toml->get_tbl()["project"]["version"].value<std::uint16_t>().value();
    EXPECT_EQ(1, test_short);
}