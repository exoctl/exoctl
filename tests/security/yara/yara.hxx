#pragma once

#include <engine/security/yara/yara.hxx>
#include <gtest/gtest.h>
#include <string>

class YaraTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            yara = new Security::Yara();
        }

        void TearDown() override
        {
            delete yara;
        }

        Security::Yara *yara;
};
