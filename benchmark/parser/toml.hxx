#pragma once

#include <benchmark/benchmark.h>
#include <engine/parser/toml.hxx>

using namespace std::string_view_literals;

class TomlBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        static constexpr std::string_view some_toml = R"(
        [project]
        name = "Engine"
        version = 1
        )"sv;

        toml = new engine::parser::Toml();
        toml->parse_buffer(some_toml);
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete toml;
    }

    engine::parser::Toml *toml;
};
