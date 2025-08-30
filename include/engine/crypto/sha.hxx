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
            Sha() = default;
            ~Sha() = default;
            friend class extend::Sha;

            [[nodiscard]] static const std::string sha256(const std::string &);
            [[nodiscard]] static const std::string sha1(const std::string &);
            [[nodiscard]] static const std::string sha512(const std::string &);
            [[nodiscard]] static const std::string sha224(const std::string &);
            [[nodiscard]] static const std::string sha384(const std::string &);
            [[nodiscard]] static const std::string sha3_256(
                const std::string &);
            [[nodiscard]] static const std::string sha3_512(
                const std::string &);

          private:
            [[nodiscard]] static const std::string digest(const std::string &,
                                                          const EVP_MD *(*) (),
                                                          size_t);
        };
    } // namespace crypto
} // namespace engine