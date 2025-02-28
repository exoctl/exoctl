#pragma once

#include <benchmark/benchmark.h>
#include <engine/bridge/focades/data/metadata/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new engine::bridge::focades::data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete metadata;
    }

    engine::bridge::focades::data::Metadata *metadata;
};