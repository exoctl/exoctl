#pragma once

#include <benchmark/benchmark.h>
#include <engine/data/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new Data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override { delete metadata; }

    Data::Metadata *metadata;
};