#include <engine/crypto/sha.hxx>
#include <engine/plugins/plugins.hxx>
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
#ifdef ENGINE_PRO
        void Sha::register_plugins()
        {
            plugins::Plugins::lua.state["_sha"] = this;

            plugins::Plugins::lua.state.new_usertype<engine::crypto::Sha>(
                "Sha",
                sol::constructors<engine::crypto::Sha()>(),
                "gen_sha1_hash",
                &Sha::gen_sha1_hash,
                "gen_sha256_hash",
                &Sha::gen_sha256_hash,
                "gen_sha512_hash",
                &Sha::gen_sha512_hash,
                "gen_sha224_hash",
                &Sha::gen_sha224_hash,
                "gen_sha384_hash",
                &Sha::gen_sha384_hash,
                "gen_sha3_256_hash",
                &Sha::gen_sha3_256_hash,
                "gen_sha3_512_hash",
                &Sha::gen_sha3_512_hash);
        }
#endif
        const std::string Sha::gen_sha1_hash(const std::string &p_str)
        {
            unsigned char hash[SHA_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha1(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format("{:02x}",
                               fmt::join(hash, hash + SHA_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha256_hash(const std::string &p_str)
        {
            unsigned char hash[SHA256_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA256_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha512_hash(const std::string &p_str)
        {
            unsigned char hash[SHA512_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha512(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA512_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha224_hash(const std::string &p_str)
        {
            unsigned char hash[SHA224_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha224(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA224_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha384_hash(const std::string &p_str)
        {
            unsigned char hash[SHA384_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha384(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA384_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha3_256_hash(const std::string &p_str)
        {
            unsigned char hash[SHA256_DIGEST_LENGTH];

            EVP_DigestInit_ex(m_ctx, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(m_ctx, p_str.c_str(), p_str.size());
            EVP_DigestFinal_ex(m_ctx, hash, nullptr);

            return fmt::format(
                "{:02x}", fmt::join(hash, hash + SHA256_DIGEST_LENGTH, ""));
        }

        const std::string Sha::gen_sha3_512_hash(const std::string &p_str)
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