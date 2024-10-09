#pragma once

#include <benchmark/benchmark.h>
#include <engine/crypto/sha.hxx>
#include <string>

class CryptoBenchmark : public benchmark::Fixture
{
  public:
    void SetUp(const ::benchmark::State &state) override
    {
        sha = new crypto::Sha();
    }

    void TearDown(const ::benchmark::State &state) override
    {
        delete sha;
    }

    crypto::Sha *sha;
};
