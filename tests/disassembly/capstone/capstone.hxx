#pragma once

#include <engine/disassembly/capstone/capstone.hxx>
#include <gtest/gtest.h>
#include <string>

class CapstoneTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        capstone = new Disassembly::Capstone(CS_ARCH_X86, CS_MODE_64);
    }

    void TearDown() override
    {
        delete capstone;
    }

    Disassembly::Capstone *capstone;
};
