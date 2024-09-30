#include <security/yara/yara.hxx>

TEST_F(YaraTest, YaraSetSignatureRuleFdTest)
{
    int status = yara->yara_set_signature_rule_fd("rules/yara/malwares/AppLaunch.yar", 
                                                  "AppLaunch",
                                                  "malwares");
    ASSERT_EQ(status, ERROR_SUCCESS);
}

TEST_F(YaraTest, YaraSetSignatureRuleMemTest)
{
    int status = yara->yara_set_signature_rule_mem("rule Malware { condition: true}",
                                                   "malware");
    ASSERT_EQ(status, ERROR_SUCCESS);
}

TEST_F(YaraTest, YaraLoadRulesFolderTest)
{
    ASSERT_NO_THROW(yara->yara_load_rules_folder("rules/"));
}
