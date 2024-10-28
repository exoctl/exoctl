#pragma once

#include <engine/crypto/sha.hxx>
#include <gtest/gtest.h>
#include <string>

class CryptoTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        sha = new engine::crypto::Sha();
    }

    void TearDown() override
    {
        delete sha;
    }

    engine::crypto::Sha *sha;
};
