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
        const std::string sha_gen_sha256_hash(const std::string &);

      private:
        EVP_MD_CTX *m_ctx;
    };
} // namespace Crypto
