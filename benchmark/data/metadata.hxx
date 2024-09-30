#pragma once

#include <benchmark/benchmark.h>
#include <engine/crow/focades/data/metadata.hxx>
#include <string>

class MetadataBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        metadata = new Focades::Data::Metadata();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete metadata;
    }

    Focades::Data::Metadata *metadata;
};