#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>

namespace Crypto
{
    class Sha
    {
      public:
        Sha();
        ~Sha();
        const void sha_gen_sha256_hash(const std::string &buffer);
        const std::string sha_get_sha256_hash();

      private:
        EVP_MD_CTX *m_ctx;
        std::string m_sha256_hash;
    };
} // namespace Crypto
