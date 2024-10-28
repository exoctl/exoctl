#pragma once

#include <benchmark/benchmark.h>
#include <engine/server/focades/data/metadata/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new engine::focades::data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete metadata;
    }

    engine::focades::data::Metadata *metadata;
};