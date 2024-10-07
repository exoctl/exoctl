#pragma once

#include <benchmark/benchmark.h>
#include <engine/parser/toml.hxx>

class TomlBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        toml = new Parser::Toml();
        toml->parser_file("./configuration.toml");
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete toml;
    }

    Parser::Toml *toml;
};
