#pragma once

#include <string>

namespace engine::focades::analysis
{
    namespace record
    {
        using File = struct File {
            std::string filename;
            std::string content; // buffer for scan
            std::string owner;
        };

        using Analysis = struct Analysis {
            int id;
            std::string file_name;
            std::string file_type;
            std::string sha256;
            std::string sha1;
            std::string sha512;
            std::string sha224;
            std::string sha384;
            std::string sha3_256;
            std::string sha3_512;
            size_t file_size;
            double file_entropy;
            std::string creation_date;
            std::string last_update_date;
            std::string file_path;
            bool is_malicious;
            bool packed;
            std::string owner;
        }; // namespace record
    } // namespace record
} // namespace engine::focades::analysis