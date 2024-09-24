#pragma once

#include <engine/crypto/sha.hxx>
#include <gtest/gtest.h>
#include <string>

class CryptoTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        sha = new Crypto::Sha();
    }

    void TearDown() override
    {
        delete sha;
    }

    Crypto::Sha *sha;
};
