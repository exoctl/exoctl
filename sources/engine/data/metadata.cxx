#include <engine/data/metadata.hxx>
#include <cmath>

namespace Data
{
Metadata::Metadata()
{
    m_entropy = 0.0;
    m_current_time = time(0);

    dto_set_field("mime_type", "none");
    dto_set_field("sha256", "none");
    dto_set_field("size", 0);
    dto_set_field("creation_date", "none");
    dto_set_field("entropy", 0.0);
}

Metadata::~Metadata() {}

const void Metadata::metadata_parse(const std::string &buffer)
{
    m_magic.magic_load_mime(buffer);
    dto_set_field("mime_type", m_magic.magic_get_mime());

    m_sha.sha_gen_sha256_hash(buffer);
    dto_set_field("sha256", m_sha.sha_get_sha256_hash());

    dto_set_field("size", (int) buffer.size());

    tm *ltm = localtime(&m_current_time);
    char cstr[11];
    strftime(cstr, sizeof(cstr), "%Y-%m-%d", ltm);

    std::string current_time = cstr;
    dto_set_field("creation_date", current_time);

    compute_entropy(buffer);
    dto_set_field("entropy", m_entropy);
}

const void Metadata::compute_entropy(const std::string &buffer)
{
    size_t map[256] = {0};

    for(size_t i = 0; i < buffer.size(); i++)  
        map[static_cast<unsigned char>(buffer[i])]++;

    double recip = 1.0 / buffer.size();
    double entropy = 0.0;

    for(size_t i = 0; i < 256; i++)
    { 
        if(map[i])
        {
            double freq = map[i] * recip;
            entropy += freq * log2(freq);
        }
    }

    m_entropy = -entropy;
}

} // namespace Data
