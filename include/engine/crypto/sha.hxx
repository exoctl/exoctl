#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <engine/crypto/extend/sha.hxx>

namespace engine
{
    namespace crypto
    {
        class Sha;

        class Sha
        {
          public:
            Sha();
            ~Sha();
            #ifdef ENGINE_PRO
            friend class extend::Sha;
#endif
            [[nodiscard]] const std::string gen_sha256_hash(
                const std::string &);
            [[nodiscard]] const std::string gen_sha1_hash(const std::string &);
            [[nodiscard]] const std::string gen_sha512_hash(
                const std::string &);
            [[nodiscard]] const std::string gen_sha224_hash(
                const std::string &);
            [[nodiscard]] const std::string gen_sha384_hash(
                const std::string &);
            [[nodiscard]] const std::string gen_sha3_256_hash(
                const std::string &);
            [[nodiscard]] const std::string gen_sha3_512_hash(
                const std::string &);

          private:
            EVP_MD_CTX *m_ctx;
        };
    } // namespace crypto
} // namespace engine