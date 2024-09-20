#include <crypto/crypto.hxx>

TEST_F(CryptoTest, ShaGenSha256Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha256_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha256_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha3_256Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha3_256_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha3_256_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha1Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha1_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha1_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha224Hash)
{
   std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha224_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha224_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha512Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha512_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha512_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha3_512Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha3_512_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha3_512_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}

TEST_F(CryptoTest, ShaGenSha384Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->sha_gen_sha384_hash(test_string);
    const std::string hash2 = sha->sha_gen_sha384_hash(test_string);

    ASSERT_EQ(hash1, hash2);
}