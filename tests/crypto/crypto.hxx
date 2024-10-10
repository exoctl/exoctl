#pragma once

#include <engine/crypto/sha.hxx>
#include <gtest/gtest.h>
#include <string>

class CryptoTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        sha = new crypto::Sha();
    }

    void TearDown() override
    {
        delete sha;
    }

    crypto::Sha *sha;
};
