#include <engine/crypto/tlsh.hxx>

namespace engine
{
    namespace crypto
    {
        const std::string Tlsh::hash(const std::string &data)
        {
            if (data.empty()) {
                return "";
            }

            ::Tlsh tlsh; 
            tlsh.update(reinterpret_cast<const unsigned char *>(data.data()),
                        data.size());
            tlsh.final();

            if (!tlsh.isValid()) {
                return ""; 
            }

            const char *hash = tlsh.getHash();
            return hash ? std::string(hash) : "";
        }

        const int Tlsh::compare(const std::string &hash_a, const std::string &hash_b)
        {
            if (hash_a.empty() || hash_b.empty()) {
                return -1;
            }

            ::Tlsh tlsh_a;
            ::Tlsh tlsh_b;

            if (tlsh_a.fromTlshStr(hash_a.c_str()) != 0 ||
                tlsh_b.fromTlshStr(hash_b.c_str()) != 0) {
                return -1;
            }

            return tlsh_a.totalDiff(&tlsh_b);
        }
    } // namespace crypto
} // namespace engine