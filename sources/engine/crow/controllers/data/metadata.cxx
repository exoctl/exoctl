#include <cmath>
#include <engine/crow/controllers/data/metadata.hxx>
#include <fmt/core.h>

namespace Controllers
{
    namespace Data
    {
        Metadata::Metadata() : m_entropy(0.0), m_current_time(time(0))
        {
            dto_set_field("mime_type", "none");
            dto_set_field("sha256", "none");
            dto_set_field("sha1", "none");
            dto_set_field("sha512", "none");
            dto_set_field("sha224", "none");
            dto_set_field("sha384", "none");
            dto_set_field("sha3-256", "none");
            dto_set_field("sha3-512", "none");
            dto_set_field("size", 0);
            dto_set_field("creation_date", "none");
            dto_set_field("entropy", m_entropy);
        }

        Metadata::~Metadata()
        {
        }

        const void Metadata::metadata_parse(const std::string &p_buffer)
        {
            m_magic.magic_load_mime(p_buffer);
            dto_set_field("mime_type", m_magic.magic_get_mime());
            dto_set_field("size", (int) p_buffer.size());

            dto_set_field("sha256", m_sha.sha_gen_sha256_hash(p_buffer));
            dto_set_field("sha1", m_sha.sha_gen_sha1_hash(p_buffer));
            dto_set_field("sha512", m_sha.sha_gen_sha512_hash(p_buffer));
            dto_set_field("sha224", m_sha.sha_gen_sha224_hash(p_buffer));
            dto_set_field("sha384", m_sha.sha_gen_sha384_hash(p_buffer));
            dto_set_field("sha3-256", m_sha.sha_gen_sha3_256_hash(p_buffer));
            dto_set_field("sha3-512", m_sha.sha_gen_sha3_512_hash(p_buffer));

            tm *ltm = localtime(&m_current_time);
            char cstr[11];
            strftime(cstr, sizeof(cstr), "%Y-%m-%d", ltm);

            dto_set_field("creation_date", std::string(cstr));

            Metadata::metadata_compute_entropy(p_buffer);
            dto_set_field("entropy", m_entropy);
        }

        const void Metadata::metadata_compute_entropy(
            const std::string &p_buffer)
        {
            size_t map[256] = {0};

            for (size_t i = 0; i < p_buffer.size(); i++)
                map[static_cast<unsigned char>(p_buffer[i])]++;

            double recip = 1.0 / p_buffer.size();
            double entropy = 0.0;

            for (size_t i = 0; i < 256; i++) {
                if (map[i]) {
                    double freq = map[i] * recip;
                    entropy += freq * log2(freq);
                }
            }

            m_entropy = -entropy;
        }
    } // namespace Data
} //  namespace Controllers