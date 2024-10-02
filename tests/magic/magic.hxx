#pragma once

#include <engine/magic/magic.hxx>
#include <gtest/gtest.h>
#include <string>

class MagicTest : public ::testing::Test
{
  protected:
    // O método SetUp será chamado antes de cada teste
    void SetUp() override
    {
        magic = new Magic::Magic();
    }

    // O método TearDown será chamado após cada teste
    void TearDown() override
    {
        delete magic;
    }

    Magic::Magic *magic;
};
