#include <cmath>
#include <engine/memory/memory.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>
#include <sources/engine/focades/analysis/metadata/metadata.hxx>

namespace engine::focades::analysis::metadata
{
    void Metadata::parse(
        const std::string &p_buffer,
        const std::function<void(metadata::record::DTO *)> &p_callback)
    {
        if (!IS_NULL(p_callback)) {
            struct metadata::record::DTO *dto = new metadata::record::DTO;

            dto->mime_type = magic.mime(p_buffer);
            dto->size = p_buffer.size();

            dto->sha256 = sha.sha256(p_buffer);
            dto->sha1 = sha.sha1(p_buffer);
            dto->sha512 = sha.sha512(p_buffer);
            dto->sha224 = sha.sha224(p_buffer);
            dto->sha384 = sha.sha384(p_buffer);
            dto->sha3_256 = sha.sha3_256(p_buffer);
            dto->tlsh = tlsh.hash(p_buffer);
            dto->sha3_512 = sha.sha3_512(p_buffer);

            time_t current_time = time(0);
            tm *ltm = localtime(&current_time);
            char cstr[11];
            strftime(cstr, sizeof(cstr), "%Y-%m-%d", ltm);

            dto->creation_date = (std::string(cstr));
            dto->entropy = Metadata::compute_entropy(p_buffer);

            p_callback(dto);
            delete dto;
        }
    }

    const engine::parser::json::Json Metadata::dto_json(
        const metadata::record::DTO *p_dto)
    {
        engine::parser::json::Json json;

        if (!IS_NULL(p_dto)) {
            json.add("mime_type", p_dto->mime_type);
            json.add("sha256", p_dto->sha256);
            json.add("tlsh", p_dto->tlsh);
            json.add("sha1", p_dto->sha1);
            json.add("sha512", p_dto->sha512);
            json.add("sha224", p_dto->sha224);
            json.add("sha384", p_dto->sha384);
            json.add("sha3_256", p_dto->sha3_256);
            json.add("sha3_512", p_dto->sha3_512);
            json.add("size", p_dto->size);
            json.add("creation_date", p_dto->creation_date);
            json.add("entropy", p_dto->entropy);
        }

        return json;
    }

    const double Metadata::compute_entropy(const std::string &p_buffer)
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
} // namespace engine::focades::analysis::metadata