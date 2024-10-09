#include <parser/toml.hxx>

TEST_F(TomlTest, TomlGetTblString)
{
    std::string tbl_string =
        toml->get_tbl()["project"]["name"].value<std::string>().value();
    EXPECT_EQ("Engine", tbl_string);
}

TEST_F(TomlTest, TomlGetTblUint16T)
{
    std::uint16_t test_short =
        toml->get_tbl()["log"]["level"].value<std::uint16_t>().value();
    EXPECT_EQ(1, test_short);
}

TEST_F(TomlTest, TomlGetTblArray)
{
    toml::array expected_array;
    expected_array.push_back("127.0.0.1");
    toml::array test_array = *toml->get_tbl()["crowpp"]["server"]["websocket"]
                                             ["context"]["whitelist"];
    ASSERT_EQ(expected_array, test_array);
}