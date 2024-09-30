#include <cmath>
#include <engine/crow/focades/data/metadata.hxx>
#include <fmt/core.h>

namespace Focades
{
    namespace Data
    {
        Metadata::Metadata()
        {
        }

        Metadata::~Metadata()
        {
        }

        void Metadata::metadata_parse(
            const std::string &p_buffer,
            const std::function<void(Structs::DTO *)> &p_callback)
        {
            struct Structs::DTO *dto = new Structs::DTO;

            m_magic.magic_load_mime(p_buffer);
            dto->mime_type.assign(m_magic.magic_get_mime());
            dto->size = (int) p_buffer.size();

            dto->sha256.assign(m_sha.sha_gen_sha256_hash(p_buffer));
            dto->sha1.assign(m_sha.sha_gen_sha1_hash(p_buffer));
            dto->sha512.assign(m_sha.sha_gen_sha512_hash(p_buffer));
            dto->sha224.assign(m_sha.sha_gen_sha224_hash(p_buffer));
            dto->sha384.assign(m_sha.sha_gen_sha384_hash(p_buffer));
            dto->sha3_256.assign(m_sha.sha_gen_sha3_256_hash(p_buffer));
            dto->sha3_512.assign(m_sha.sha_gen_sha3_512_hash(p_buffer));

            time_t current_time = time(0);
            tm *ltm = localtime(&current_time);
            char cstr[11];
            strftime(cstr, sizeof(cstr), "%Y-%m-%d", ltm);

            dto->creation_date.assign(std::string(cstr));
            dto->entropy = Metadata::metadata_compute_entropy(p_buffer);

            p_callback(dto);
            delete dto;
        }

        const Parser::Json Metadata::metadata_dto_json(
            const Structs::DTO *p_dto)
        {
            Parser::Json json;
            json.json_add_member_string("mime_type", p_dto->mime_type);
            json.json_add_member_string("sha256", p_dto->sha256);
            json.json_add_member_string("sha1", p_dto->sha1);
            json.json_add_member_string("sha512", p_dto->sha512);
            json.json_add_member_string("sha224", p_dto->sha224);
            json.json_add_member_string("sha384", p_dto->sha384);
            json.json_add_member_string("sha3_256", p_dto->sha3_256);
            json.json_add_member_string("sha3_512", p_dto->sha3_512);
            json.json_add_member_int("size", p_dto->size);
            json.json_add_member_string("creation_date", p_dto->creation_date);
            json.json_add_member_double("entropy", p_dto->entropy);
            return json;
        }

        const double Metadata::metadata_compute_entropy(
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

            return -entropy;
        }
    } // namespace Data
} // namespace Focades