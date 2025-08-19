#pragma once

#include <benchmark/benchmark.h>
#include <engine/parser/json/json.hxx>

class JsonBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        json = new engine::parser::json::Json();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete json;
    }

    engine::parser::json::Json *json;
};
