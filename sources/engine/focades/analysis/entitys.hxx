#pragma once

#include <engine/database/entitys.hxx>
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
            int id; // automatically generated
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
            bool is_packed;
            std::string owner;
        }; // namespace record
    } // namespace record
} // namespace engine::focades::analysis

namespace soci
{
    template <>
    struct type_conversion<engine::focades::analysis::record::Analysis> {
        using base_type = values;

        static void from_base(const engine::database::SociValues &v,
                              engine::database::SociIndicator /* ind */,
                              engine::focades::analysis::record::Analysis &analysis)
        {
            analysis.id = v.get<int>("id");
            analysis.file_name = v.get<std::string>("file_name");
            analysis.file_type = v.get<std::string>("file_type");
            analysis.sha256 = v.get<std::string>("sha256");
            analysis.sha1 = v.get<std::string>("sha1");
            analysis.sha512 = v.get<std::string>("sha512");
            analysis.sha224 = v.get<std::string>("sha224");
            analysis.sha384 = v.get<std::string>("sha384");
            analysis.sha3_256 = v.get<std::string>("sha3_256");
            analysis.sha3_512 = v.get<std::string>("sha3_512");
            analysis.file_size = v.get<std::size_t>("file_size");
            analysis.file_entropy = v.get<double>("file_entropy");
            analysis.creation_date = v.get<std::string>("creation_date");
            analysis.last_update_date = v.get<std::string>("last_update_date");
            analysis.file_path = v.get<std::string>("file_path");
            analysis.is_malicious = v.get<int>("is_malicious") != 0;
            analysis.is_packed = v.get<int>("is_packed") != 0;
            analysis.owner = v.get<std::string>("owner");
        }

        static void to_base(const engine::focades::analysis::record::Analysis &analysis,
                            engine::database::SociValues &v,
                            engine::database::SociIndicator &ind)
        {
            v.set("file_name", analysis.file_name);
            v.set("file_type", analysis.file_type);
            v.set("sha256", analysis.sha256);
            v.set("sha1", analysis.sha1);
            v.set("sha512", analysis.sha512);
            v.set("sha224", analysis.sha224);
            v.set("sha384", analysis.sha384);
            v.set("sha3_256", analysis.sha3_256);
            v.set("sha3_512", analysis.sha3_512);
            v.set("file_size", analysis.file_size);
            v.set("file_entropy", analysis.file_entropy);
            v.set("creation_date", analysis.creation_date);
            v.set("last_update_date", analysis.last_update_date);
            v.set("file_path", analysis.file_path);
            v.set("is_malicious", analysis.is_malicious ? 1 : 0);
            v.set("is_packed", analysis.is_packed ? 1 : 0);
            v.set("owner", analysis.owner);
            ind = engine::database::SociIndicator::i_ok;
        }
    };
} // namespace soci