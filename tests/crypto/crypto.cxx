#include <crypto/crypto.hxx>

void VerifyHashLength(const std::string &hash, size_t expected_length)
{
    ASSERT_EQ(hash.size(), expected_length) << "Hash length mismatch";
}

TEST_F(CryptoTest, ShaGenSha256Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha256_hash(test_string);
    const std::string hash2 = sha->gen_sha256_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 64); // SHA-256 hash should be 64 hex characters
}

TEST_F(CryptoTest, ShaGenSha3_256Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha3_256_hash(test_string);
    const std::string hash2 = sha->gen_sha3_256_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 64); // SHA3-256 hash should be 64 hex characters
}

// Testes para SHA-1
TEST_F(CryptoTest, ShaGenSha1Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha1_hash(test_string);
    const std::string hash2 = sha->gen_sha1_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 40); // SHA-1 hash should be 40 hex characters
}

TEST_F(CryptoTest, ShaGenSha224Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha224_hash(test_string);
    const std::string hash2 = sha->gen_sha224_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 56); // SHA-224 hash should be 56 hex characters
}

TEST_F(CryptoTest, ShaGenSha512Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha512_hash(test_string);
    const std::string hash2 = sha->gen_sha512_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 128); // SHA-512 hash should be 128 hex characters
}

TEST_F(CryptoTest, ShaGenSha3_512Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha3_512_hash(test_string);
    const std::string hash2 = sha->gen_sha3_512_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 128); // SHA3-512 hash should be 128 hex characters
}

TEST_F(CryptoTest, ShaGenSha384Hash)
{
    std::string test_string = "the best engine";

    const std::string hash1 = sha->gen_sha384_hash(test_string);
    const std::string hash2 = sha->gen_sha384_hash(test_string);

    ASSERT_EQ(hash1, hash2) << "Hashes from the same input should be equal";
    VerifyHashLength(hash1, 96); // SHA-384 hash should be 96 hex characters
}

TEST_F(CryptoTest, ShaGenEmptyString)
{
    std::string empty_string = "";

    const std::string hash_sha256 = sha->gen_sha256_hash(empty_string);
    const std::string hash_sha3_256 = sha->gen_sha3_256_hash(empty_string);
    const std::string hash_sha512 = sha->gen_sha512_hash(empty_string);

    ASSERT_FALSE(hash_sha256.empty()) << "Hash should not be empty";
    ASSERT_FALSE(hash_sha3_256.empty()) << "Hash should not be empty";
    ASSERT_FALSE(hash_sha512.empty()) << "Hash should not be empty";
}

TEST_F(CryptoTest, ShaGenDifferentStrings)
{
    std::string string1 = "the best engine";
    std::string string2 = "another engine";

    const std::string hash1 = sha->gen_sha256_hash(string1);
    const std::string hash2 = sha->gen_sha256_hash(string2);

    ASSERT_NE(hash1, hash2)
        << "Hashes from different inputs should not be equal";
}

TEST_F(CryptoTest, ShaGenSpecialCharacters)
{
    std::string special_string = "engine@123!$%^&*()";

    const std::string hash = sha->gen_sha256_hash(special_string);
    ASSERT_FALSE(hash.empty())
        << "Hash should not be empty for special characters";
    VerifyHashLength(hash, 64); // SHA-256 hash should be 64 hex characters
}

TEST_F(CryptoTest, ShaGenLargeString)
{
    std::string large_string(10000, 'a');

    const std::string hash = sha->gen_sha256_hash(large_string);
    ASSERT_FALSE(hash.empty()) << "Hash should not be empty for large input";
    VerifyHashLength(hash, 64); // SHA-256 hash should be 64 hex characters
}