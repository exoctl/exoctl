#pragma once

#include <benchmark/benchmark.h>
#include <engine/crow/controllers/data/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new Controllers::Data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override { delete metadata; }

    Controllers::Data::Metadata *metadata;
};