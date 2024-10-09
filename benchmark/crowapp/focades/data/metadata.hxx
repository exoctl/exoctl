#pragma once

#include <benchmark/benchmark.h>
#include <engine/crowapp/focades/data/metadata/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new focades::data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete metadata;
    }

    focades::data::Metadata *metadata;
};