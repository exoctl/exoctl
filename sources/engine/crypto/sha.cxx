#include <engine/crypto/sha.hxx>
#include <fmt/core.h>
#include <iomanip>
#include <sstream>

namespace Crypto
{
Sha::Sha() : m_ctx(EVP_MD_CTX_new())
{
    EVP_DigestInit_ex(m_ctx, EVP_sha256(), NULL);
}

Sha::~Sha() { EVP_MD_CTX_free(m_ctx); }

const void Sha::sha_gen_sha256_hash(const std::string &str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];

    EVP_DigestUpdate(m_ctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(m_ctx, hash, NULL);

    m_sha256_hash.clear();
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        m_sha256_hash += fmt::format("{:02x}", hash[i]);
    }
}

const std::string Sha::sha_get_sha256_hash() { return m_sha256_hash; }

} // namespace Crypto
