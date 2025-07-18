#include <engine/crypto/sha.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace engine
{
    namespace crypto
    {
        Sha::Sha() : m_ctx(EVP_MD_CTX_new())
        {
        }

        Sha::~Sha()
        {
            EVP_MD_CTX_free(m_ctx);
        }

        const std::string Sha::sha1(const std::string &p_str)
        {
            unsigned char hash[SHA_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha1(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format("{:02x}",
                               fmt::join(hash, hash + SHA_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha256(const std::string &p_str)
        {
            unsigned char hash[SHA256_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA256_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha512(const std::string &p_str)
        {
            unsigned char hash[SHA512_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha512(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA512_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha224(const std::string &p_str)
        {
            unsigned char hash[SHA224_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha224(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA224_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha384(const std::string &p_str)
        {
            unsigned char hash[SHA384_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha384(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA384_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha3_256(const std::string &p_str)
        {
            unsigned char hash[SHA256_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA256_DIGEST_LENGTH, ""));
        }

        const std::string Sha::sha3_512(const std::string &p_str)
        {
            unsigned char hash[SHA512_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha3_512(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA512_DIGEST_LENGTH, ""));
        }

    } // namespace crypto
} // namespace engine