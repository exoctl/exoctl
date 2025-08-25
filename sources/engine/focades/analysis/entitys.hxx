#pragma once

#include <engine/database/entitys.hxx>
#include <string>

namespace engine::focades::analysis
{
    namespace record
    {
        struct File {
            std::string filename;
            std::string content; // buffer for scan
            std::string owner;
        };

        struct Family {
            int id;
            std::string name;
            std::string description;
        };

        struct Tag {
            int id;
            std::string name;
            std::string description;
        };

        struct AnalysisTag {
            int analysis_id;
            int tag_id;
        };

        struct Analysis {
            int id;
            std::string file_name;
            std::string file_type;
            std::string sha256;
            std::string sha1;
            std::string sha512;
            std::string sha224;
            std::string tlsh;
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
            std::string description;
            std::string owner;
            int family_id;
        };
    } // namespace record
} // namespace engine::focades::analysis

namespace soci
{
    template <>
    struct type_conversion<engine::focades::analysis::record::Family> {
        using base_type = values;

        static void from_base(const engine::database::SociValues &v,
                              engine::database::SociIndicator /* ind */,
                              engine::focades::analysis::record::Family &family)
        {
            family.id = v.get<int>("id");
            family.name = v.get<std::string>("name");
            family.description = v.get<std::string>("description");
        }

        static void to_base(
            const engine::focades::analysis::record::Family &family,
            engine::database::SociValues &v,
            engine::database::SociIndicator &ind)
        {
            v.set("name", family.name);
            v.set("description", family.description);
            ind = engine::database::SociIndicator::i_ok;
        }
    };

    template <> struct type_conversion<engine::focades::analysis::record::Tag> {
        using base_type = values;

        static void from_base(const engine::database::SociValues &v,
                              engine::database::SociIndicator /* ind */,
                              engine::focades::analysis::record::Tag &tag)
        {
            tag.id = v.get<int>("id");
            tag.name = v.get<std::string>("name");
            tag.description = v.get<std::string>("description");
        }

        static void to_base(const engine::focades::analysis::record::Tag &tag,
                            engine::database::SociValues &v,
                            engine::database::SociIndicator &ind)
        {
            v.set("name", tag.name);
            v.set("description", tag.description);
            ind = engine::database::SociIndicator::i_ok;
        }
    };

    template <>
    struct type_conversion<engine::focades::analysis::record::AnalysisTag> {
        using base_type = values;

        static void from_base(
            const engine::database::SociValues &v,
            engine::database::SociIndicator /* ind */,
            engine::focades::analysis::record::AnalysisTag &analysis_tag)
        {
            analysis_tag.analysis_id = v.get<int>("analysis_id");
            analysis_tag.tag_id = v.get<int>("tag_id");
        }

        static void to_base(
            const engine::focades::analysis::record::AnalysisTag &analysis_tag,
            engine::database::SociValues &v,
            engine::database::SociIndicator &ind)
        {
            v.set("analysis_id", analysis_tag.analysis_id);
            v.set("tag_id", analysis_tag.tag_id);
            ind = engine::database::SociIndicator::i_ok;
        }
    };

    template <>
    struct type_conversion<engine::focades::analysis::record::Analysis> {
        using base_type = values;

        static void from_base(
            const engine::database::SociValues &v,
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
            analysis.tlsh = v.get<std::string>("tlsh");
            analysis.sha3_512 = v.get<std::string>("sha3_512");
            analysis.file_size =
                static_cast<size_t>(v.get<long long>("file_size", 0));
            analysis.file_entropy = v.get<double>("file_entropy");
            analysis.creation_date = v.get<std::string>("creation_date");
            analysis.last_update_date = v.get<std::string>("last_update_date");
            analysis.file_path = v.get<std::string>("file_path");
            analysis.is_malicious = v.get<bool>("is_malicious") != 0;
            analysis.is_packed = v.get<bool>("is_packed") != 0;
            analysis.description = v.get<std::string>("description");
            analysis.owner = v.get<std::string>("owner");
            analysis.family_id = v.get<int>("family_id", 0); // 0 se NULL
        }

        static void to_base(
            const engine::focades::analysis::record::Analysis &analysis,
            engine::database::SociValues &v,
            engine::database::SociIndicator &ind)
        {
            v.set("file_name", analysis.file_name);
            v.set("file_type", analysis.file_type);
            v.set("sha256", analysis.sha256);
            v.set("sha1", analysis.sha1);
            v.set("sha512", analysis.sha512);
            v.set("sha224", analysis.sha224);
            v.set("tlsh", analysis.tlsh);
            v.set("sha384", analysis.sha384);
            v.set("sha3_256", analysis.sha3_256);
            v.set("sha3_512", analysis.sha3_512);
            v.set("file_size", static_cast<long long>(analysis.file_size));
            v.set("file_entropy", analysis.file_entropy);
            v.set("creation_date", analysis.creation_date);
            v.set("last_update_date", analysis.last_update_date);
            v.set("file_path", analysis.file_path);
            v.set("is_malicious", analysis.is_malicious ? 1 : 0);
            v.set("is_packed", analysis.is_packed ? 1 : 0);
            v.set("description", analysis.description);
            v.set("owner", analysis.owner);
            v.set("family_id", analysis.family_id);
            ind = engine::database::SociIndicator::i_ok;
        }
    };
} // namespace soci