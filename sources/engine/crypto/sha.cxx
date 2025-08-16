#include <engine/crypto/sha.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace engine
{
    namespace crypto
    {
        const std::string Sha::digest(const std::string &input,
                                      const EVP_MD *(*evp_func)(),
                                      size_t length)
        {
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len = 0;

            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (!ctx)
                throw std::runtime_error("EVP_MD_CTX_new failed");

            EVP_DigestInit_ex(ctx, evp_func(), nullptr);
            EVP_DigestUpdate(ctx, input.data(), input.size());
            EVP_DigestFinal_ex(ctx, hash, &hash_len);

            EVP_MD_CTX_free(ctx);

            return fmt::format("{:02x}", fmt::join(hash, hash + hash_len, ""));
        }

        const std::string Sha::sha1(const std::string &p_str)
        {
            return digest(p_str, EVP_sha1, SHA_DIGEST_LENGTH);
        }

        const std::string Sha::sha224(const std::string &p_str)
        {
            return digest(p_str, EVP_sha224, SHA224_DIGEST_LENGTH);
        }

        const std::string Sha::sha256(const std::string &p_str)
        {
            return digest(p_str, EVP_sha256, SHA256_DIGEST_LENGTH);
        }

        const std::string Sha::sha384(const std::string &p_str)
        {
            return digest(p_str, EVP_sha384, SHA384_DIGEST_LENGTH);
        }

        const std::string Sha::sha512(const std::string &p_str)
        {
            return digest(p_str, EVP_sha512, SHA512_DIGEST_LENGTH);
        }

        const std::string Sha::sha3_256(const std::string &p_str)
        {
            return digest(p_str, EVP_sha3_256, SHA256_DIGEST_LENGTH);
        }

        const std::string Sha::sha3_512(const std::string &p_str)
        {
            return digest(p_str, EVP_sha3_512, SHA512_DIGEST_LENGTH);
        }

    } // namespace crypto
} // namespace engine
