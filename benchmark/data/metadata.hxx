#pragma once

#include <benchmark/benchmark.h>
#include <engine/crowapp/focades/data/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new focades::Data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete metadata;
    }

    focades::Data::Metadata *metadata;
};