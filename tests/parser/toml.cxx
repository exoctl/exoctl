#include <parser/toml.hxx>

TEST_F(TomlTest, TomlGetTblString)
{
    std::string tbl_string = toml->toml_get_tbl_string("project", "name");
    EXPECT_EQ("Engine", tbl_string);
}

TEST_F(TomlTest, TomlGetTblUint16T)
{
    std::uint16_t test_short = toml->toml_get_tbl_uint16_t("log", "level");
    EXPECT_EQ(1, test_short);
}

TEST_F(TomlTest, TomlGetTblArray)
{
    toml::array expected_array;
    expected_array.push_back("127.0.0.1");
    toml::array test_array =
        toml->toml_get_tbl_array("crow", "websocket_conn_whitelist");
    ASSERT_EQ(expected_array, test_array);
}
