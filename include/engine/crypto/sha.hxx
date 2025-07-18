#pragma once

#include <engine/crypto/extend/sha.hxx>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>

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
            friend class extend::Sha;

            [[nodiscard]] const std::string sha256(const std::string &);
            [[nodiscard]] const std::string sha1(const std::string &);
            [[nodiscard]] const std::string sha512(const std::string &);
            [[nodiscard]] const std::string sha224(const std::string &);
            [[nodiscard]] const std::string sha384(const std::string &);
            [[nodiscard]] const std::string sha3_256(const std::string &);
            [[nodiscard]] const std::string sha3_512(const std::string &);

          private:
            EVP_MD_CTX *m_ctx;
        };
    } // namespace crypto
} // namespace engine