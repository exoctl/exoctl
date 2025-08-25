#pragma once

#include <string>

namespace engine::focades::analysis::metadata::record
{
    using DTO = struct DTO {
        std::string mime_type;
        std::string sha256;
        std::string sha1;
        std::string sha512;
        std::string sha224;
        std::string sha384;
        std::string sha3_256;
        std::string tlsh;
        std::string sha3_512;
        size_t size;
        std::string creation_date;
        double entropy;
    };
} // namespace engine::focades::analysis::metadata::record
