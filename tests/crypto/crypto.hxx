#pragma once

#include <engine/crypto/sha.hxx>
#include <gtest/gtest.h>
#include <string>

class CryptoTest : public ::testing::Test
{
  protected:
    // O método SetUp será chamado antes de cada teste
    void SetUp() override
    {
        sha = new Crypto::Sha();
    }

    // O método TearDown será chamado após cada teste
    void TearDown() override
    {
        delete sha;
    }

    Crypto::Sha *sha;
};
