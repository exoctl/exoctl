#pragma once

#include <engine/parser/toml.hxx>
#include <gtest/gtest.h>

using namespace std::string_view_literals;

class TomlTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        static constexpr std::string_view some_toml = R"(
        [project]
        name = "Engine"
        version = 1
        )"sv;

        toml = new engine::parser::Toml();
        toml->parse_buffer(some_toml);
    }

    void TearDown() override
    {
        delete toml;
    }

    engine::parser::Toml *toml;
};