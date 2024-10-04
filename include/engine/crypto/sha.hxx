#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>

namespace crypto
{
    class Sha
    {
      public:
        Sha();
        ~Sha();

        [[nodiscard]] const std::string sha_gen_sha256_hash(
            const std::string &);
        [[nodiscard]] const std::string sha_gen_sha1_hash(const std::string &);
        [[nodiscard]] const std::string sha_gen_sha512_hash(
            const std::string &);
        [[nodiscard]] const std::string sha_gen_sha224_hash(
            const std::string &);
        [[nodiscard]] const std::string sha_gen_sha384_hash(
            const std::string &);
        [[nodiscard]] const std::string sha_gen_sha3_256_hash(
            const std::string &);
        [[nodiscard]] const std::string sha_gen_sha3_512_hash(
            const std::string &);

      private:
        EVP_MD_CTX *m_ctx;
    };
} // namespace crypto
