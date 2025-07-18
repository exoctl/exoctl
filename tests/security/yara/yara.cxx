#include <security/yara/yara.hxx>

TEST_F(YaraTest, YaraSetSignatureRuleMemTest)
{
    const int status =
        yara->set_rule_buff("rule Malware { condition: true}", "malware");
    ASSERT_EQ(status, ERROR_SUCCESS);
}

TEST_F(YaraTest, YaraLoadRulesFolderTest)
{
    ASSERT_NO_THROW(yara->set_rules_folder("./"));
}