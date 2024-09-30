#pragma once

#include <benchmark/benchmark.h>
#include <engine/parser/json.hxx>

class JsonBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        json = new Parser::Json();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete json;
    }

    Parser::Json *json;
};
