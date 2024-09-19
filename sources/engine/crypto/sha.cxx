#include <engine/crypto/sha.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace Crypto
{
    Sha::Sha() : m_ctx(EVP_MD_CTX_new())
    {
    }

    Sha::~Sha()
    {
        EVP_MD_CTX_free(m_ctx);
    }

    const std::string Sha::sha_gen_sha256_hash(const std::string &p_str)
    {
        unsigned char hash[SHA256_DIGEST_LENGTH];

        EVP_DigestInit_ex(m_ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
        EVP_DigestFinal_ex(m_ctx, hash, nullptr);
        
        return fmt::format("{:02x}",
                           fmt::join(hash, hash + SHA256_DIGEST_LENGTH, ""));
    }

} // namespace Crypto
