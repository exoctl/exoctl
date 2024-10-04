#pragma once

#include <engine/security/yara/yara.hxx>
#include <gtest/gtest.h>
#include <string>

class YaraTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        yara = new security::Yara();
    }

    void TearDown() override
    {
        delete yara;
    }

    security::Yara *yara;
};
