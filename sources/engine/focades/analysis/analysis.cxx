#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/crypto/tlsh.hxx>
#include <engine/database/database.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <fmt/format.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>

namespace engine::focades::analysis
{
    Analysis::Analysis()
        : metadata(std::make_shared<focades::analysis::metadata::Metadata>()),
          clamav(std::make_shared<
                 focades::analysis::threats::av::clamav::Clamav>()),
          yara(std::make_shared<focades::analysis::threats::yara::Yara>())
    {
    }

    void Analysis::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<focades::analysis::Analysis>(
            "Analysis",
            "yara_rules_path",
            sol::property(
                [](focades::analysis::Analysis &self) -> const std::string {
                    if (self.yara)
                        return self.yara->rules_path;
                    return "";
                }),
            sol::meta_function::index,
            [](focades::analysis::Analysis &self,
               const std::string &key,
               sol::this_state ts) {
                sol::state_view lua(ts);

                if (key == "clamav" && self.clamav)
                    return sol::make_object(lua, std::ref(self.clamav->clamav));

                if (key == "yara" && self.yara)
                    return sol::make_object(lua, std::ref(self.yara->yara));

                if (self.metadata) {
                    if (key == "sha")
                        return sol::make_object(lua,
                                                std::ref(self.metadata->sha));

                    if (key == "magic")
                        return sol::make_object(lua,
                                                std::ref(self.metadata->magic));
                }

                return sol::make_object(lua, sol::nil);
            });
    }

    void Analysis::setup(configuration::Configuration &p_config,
                         logging::Logging &p_log)
    {
        m_config = &p_config;
        m_log = &p_log;

        packed_entropy = m_config->get("focades.analysis.packed.entropy")
                             .value<double>()
                             .value();

        family_tlsh =
            m_config->get("focades.analysis.family.tlsh").value<int>().value();

        yara->setup(p_config);
        clamav->setup(p_config);
    }

    void Analysis::load() const
    {
        TRY_BEGIN()
        m_log->info("Loading rules yara ...");
        yara->load();

        m_log->info("Loading rules clamav ...");
        clamav->load([&](unsigned int p_total_rules) {
            m_log->info(
                "Successfully loaded rules. Total Clamav rules count: {:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            m_log->error("{}", e.what());
            throw exception::Load(e.what());
        })
    }

    const record::Analysis Analysis::scan(const record::File &p_file)
    {
        record::Analysis analysis;
        analysis.owner = p_file.owner;

        metadata->parse(p_file.content,
                        [&](focades::analysis::metadata::record::DTO *p_dto) {
                            analysis.file_name = analysis.sha256 =
                                p_dto->sha256;
                            analysis.sha1 = p_dto->sha1;
                            analysis.sha512 = p_dto->sha512;
                            analysis.sha224 = p_dto->sha224;
                            analysis.sha384 = p_dto->sha384;
                            analysis.sha3_256 = p_dto->sha3_256;
                            analysis.sha3_512 = p_dto->sha3_512;
                            analysis.file_type = p_dto->mime_type;
                            analysis.file_entropy = p_dto->entropy;
                            analysis.tlsh = p_dto->tlsh;
                            analysis.last_update_date = analysis.creation_date =
                                p_dto->creation_date;
                        });

        TRY_BEGIN()
        analysis.is_malicious = [&]() -> bool {
            bool result = false;
            yara->scan(
                p_file.content,
                [&](focades::analysis::threats::yara::record::DTO *p_dto) {
                    if (p_dto->math_status ==
                        focades::analysis::threats::yara::type::Scan::match) {
                        result = true;
                    }
                });

            clamav->scan(p_file.content,
                         [&](focades::analysis::threats::av::clamav::record::DTO
                                 *p_dto) {
                             if (p_dto->math_status ==
                                 security::av::clamav::type::Scan::virus)
                                 result = true;
                         });

            return result;
        }();
        TRY_END()
        CATCH(security::av::clamav::exception::Scan, {
            throw exception::Scan(fmt::format(
                "Error scan clamav from file '{}'", analysis.sha256));
        })
        CATCH(security::yara::exception::Scan, {
            throw exception::Scan(
                fmt::format("Error scan yara from file '{}'", analysis.sha256));
        })

        analysis.is_packed = (analysis.file_entropy >= packed_entropy);
        analysis.file_size = p_file.content.size();
        analysis.file_path = filesystem::Filesystem::path;
        analysis.description =
            (analysis.is_malicious ? "File detected as malicious"
                                   : "File not detected as malicious");

        // Assign family ID to analysis based on TLSH distance
        analysis.family_id = [&]() -> int {
            int best_family = 0;

            for (const auto &anal : Analysis::analysis_table_get_all()) {
                if (anal.file_type != analysis.file_type ||
                    anal.sha256 == analysis.sha256) {
                    continue;
                }

                int dist = crypto::Tlsh::compare(anal.tlsh, analysis.tlsh);
                // Check if distance satisfies the per-family threshold
                if (dist <= family_tlsh) {
                    family_tlsh = dist;
                    best_family = anal.family_id;
                    fmt::print("New best family: {} (distance {})\n",
                               best_family,
                               family_tlsh);
                    if (dist == 0) {
                        break;
                    }
                }
            }

            return best_family;
        }();

        return analysis;
    }

    void Analysis::file_write(const record::File &p_file)
    {
        filesystem::record::EnqueueTask task;
        task.file.content.assign(p_file.content);
        task.file.filename.assign(p_file.filename);

        if (!filesystem::Filesystem::is_exists(task.file)) {
            filesystem::Filesystem::enqueue_write(task);
        }
    }

    void Analysis::file_read(record::File &p_file)
    {
        filesystem::record::File file;
        file.filename.assign(p_file.filename);
        if (filesystem::Filesystem::is_exists(file)) {
            filesystem::Filesystem::read(file);
            p_file.content.assign(file.content);
        }
    }

    const bool Analysis::analysis_table_exists()
    {
        return database::Database::is_table_exists("analysis");
    }

    const std::vector<record::Analysis> Analysis::analysis_table_get_all()
    {
        std::vector<record::Analysis> results;

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Analysis> rs =
            (sql.prepare
             << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
                "sha224, sha384, sha3_256, sha3_512, file_size, "
                "file_entropy, "
                "creation_date, last_update_date, file_path, is_malicious, "
                "is_packed, owner, family_id, tlsh, description "
                "FROM analysis");

        results.assign(rs.begin(), rs.end());

        m_log->info("Successfully retrieved {} analysis records",
                    results.size());
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve analysis records: {}", e.what());
        })

        return results;
    }

    void Analysis::analysis_table_insert(const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            m_log->error("Table for analysis not found, cannot insert record "
                         "for sha256 '{}'",
                         p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO analysis ("
               "file_name, file_type, sha256, sha1, sha512, sha224, "
               "sha384, sha3_256, sha3_512, file_size, file_entropy, "
               "creation_date, last_update_date, file_path, is_malicious, "
               "is_packed, owner, family_id, tlsh, description) "
               "VALUES (:file_name, :file_type, :sha256, :sha1, "
               ":sha512, :sha224, :sha384, :sha3_256, :sha3_512, "
               ":file_size, :file_entropy, :creation_date, "
               ":last_update_date, :file_path, :is_malicious, :is_packed, "
               ":owner, :family_id, :tlsh, :description)",
            soci::use(p_analysis);

        m_log->info("Successfully inserted analysis record for sha256 '{}'",
                    p_analysis.sha256);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to insert analysis for sha256 '{}': {}",
                         p_analysis.sha256,
                         e.what());
        })
    }

    void Analysis::analysis_table_update(const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            m_log->error("Table for analysis not found, reanalyze '{}' the "
                         "file to save it in the database",
                         p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "UPDATE analysis SET "
               "file_name = :file_name, "
               "file_type = :file_type, "
               "sha1 = :sha1, "
               "sha512 = :sha512, "
               "sha224 = :sha224, "
               "sha384 = :sha384, "
               "sha3_256 = :sha3_256, "
               "sha3_512 = :sha3_512, "
               "file_size = :file_size, "
               "file_entropy = :file_entropy, "
               "last_update_date = :last_update_date, "
               "file_path = :file_path, "
               "is_malicious = :is_malicious, "
               "is_packed = :is_packed, "
               "owner = :owner,"
               "tlsh = :tlsh,"
               "family_id = :family_id,"
               "description = :description "
               "WHERE sha256 = :sha256",
            soci::use(p_analysis);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to update analysis for sha256 '{}': {}",
                         p_analysis.sha256,
                         e.what());
        })
    }

    const bool Analysis::analysis_table_exists_by_sha256(
        const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            m_log->error("Table for analysis not found, cannot check existence "
                         "for SHA256 '{}'",
                         p_analysis.sha256);
            return false;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        int exists;
        sql << "SELECT EXISTS (SELECT 1 FROM analysis WHERE sha256 = "
               ":sha256)",
            soci::use(p_analysis.sha256), soci::into(exists);

        if (sql.got_data()) {
            return exists != 0;
        } else {
            m_log->warn("No result returned when checking existence for "
                        "SHA256 '{}'",
                        p_analysis.sha256);
            return false;
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to check existence for SHA256 '{}': {}",
                         p_analysis.sha256,
                         e.what());
        })

        return false;
    }

    const record::Analysis Analysis::analysis_table_get_by_id(const int p_id)
    {
        if (!analysis_table_exists()) {
            m_log->error("Table for analysis not found, cannot retrieve record "
                         "with ID '{}'",
                         p_id);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Analysis result;
        sql << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
               "sha224, sha384, sha3_256, sha3_512, file_size, "
               "file_entropy, creation_date, last_update_date, file_path, "
               "is_malicious, is_packed, owner, family_id, tlsh, "
               "description "
               "FROM analysis WHERE id = :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No analysis record found for ID '{}'", p_id);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error(
                "Failed to retrieve analysis for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Analysis Analysis::analysis_table_get_by_sha256(
        const std::string &p_sha256)
    {
        if (!analysis_table_exists()) {
            m_log->error("Table for analysis not found, cannot retrieve record "
                         "with SHA256 '{}'",
                         p_sha256);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Analysis result;
        sql << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
               "sha224, sha384, sha3_256, sha3_512, file_size, "
               "file_entropy, creation_date, last_update_date, file_path, "
               "is_malicious, is_packed, owner, family_id, tlsh, "
               "description "
               "FROM analysis WHERE sha256 = :sha256",
            soci::use(p_sha256), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No analysis record found for SHA256 '{}'", p_sha256);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve analysis for SHA256 '{}': {}",
                         p_sha256,
                         e.what());
        })
        return {};
    }

    const bool Analysis::family_table_exists()
    {
        return database::Database::is_table_exists("family");
    }

    void Analysis::family_table_insert(const record::Family &p_family)
    {
        if (!family_table_exists()) {
            m_log->error("Table for family not found, cannot insert record for "
                         "name '{}'",
                         p_family.name);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO family (name, description) "
               "VALUES (:name, :description)",
            soci::use(p_family);

        m_log->info("Successfully inserted family record for name '{}'",
                    p_family.name);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to insert family for name '{}': {}",
                         p_family.name,
                         e.what());
        })
    }

    const std::vector<record::Family> Analysis::family_table_get_all()
    {
        std::vector<record::Family> results;

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Family> rs =
            (sql.prepare << "SELECT id, name, description FROM family");

        results.assign(rs.begin(), rs.end());

        m_log->info("Successfully retrieved {} family records", results.size());
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve family records: {}", e.what());
        })

        return results;
    }

    const record::Family Analysis::family_table_get_by_id(const int p_id)
    {
        if (!family_table_exists()) {
            m_log->error("Table for family not found, cannot retrieve record "
                         "with ID '{}'",
                         p_id);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Family result;
        sql << "SELECT id, name, description FROM family WHERE "
               "id = :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No family record found for ID '{}'", p_id);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error(
                "Failed to retrieve family for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Family Analysis::family_table_get_by_name(
        const std::string &p_name)
    {
        if (!family_table_exists()) {
            m_log->error("Table for family not found, cannot retrieve record "
                         "with name '{}'",
                         p_name);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Family result;
        sql << "SELECT id, name, description FROM family WHERE "
               "name = :name",
            soci::use(p_name), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No family record found for name '{}'", p_name);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve family for name '{}': {}",
                         p_name,
                         e.what());
        })
        return {};
    }

    const bool Analysis::tag_table_exists()
    {
        return database::Database::is_table_exists("tags");
    }

    void Analysis::tag_table_insert(const record::Tag &p_tag)
    {
        if (!tag_table_exists()) {
            m_log->error("Table for tags not found, cannot insert record "
                         "for name '{}'",
                         p_tag.name);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO tags (name, description) "
               "VALUES (:name, :description)",
            soci::use(p_tag);

        m_log->info("Successfully inserted tag record for name '{}'",
                    p_tag.name);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error(
                "Failed to insert tag for name '{}': {}", p_tag.name, e.what());
        })
    }

    const std::vector<record::Tag> Analysis::tag_table_get_all()
    {
        std::vector<record::Tag> results;

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Tag> rs =
            (sql.prepare << "SELECT id, name, description FROM tags");

        results.assign(rs.begin(), rs.end());

        m_log->info("Successfully retrieved {} tag records", results.size());
        TRY_END()
        CATCH(database::SociError,
              { m_log->error("Failed to retrieve tag records: {}", e.what()); })

        return results;
    }

    const record::Tag Analysis::tag_table_get_by_id(const int p_id)
    {
        if (!tag_table_exists()) {
            m_log->error("Table for tags not found, cannot retrieve record "
                         "with ID '{}'",
                         p_id);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Tag result;
        sql << "SELECT id, name, description FROM tags WHERE id "
               "= :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No tag record found for ID '{}'", p_id);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error(
                "Failed to retrieve tag for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Tag Analysis::tag_table_get_by_name(const std::string &p_name)
    {
        if (!tag_table_exists()) {
            m_log->error("Table for tags not found, cannot retrieve record "
                         "with name '{}'",
                         p_name);
            return {};
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        record::Tag result;
        sql << "SELECT id, name, description FROM tags WHERE "
               "name = :name",
            soci::use(p_name), soci::into(result);

        if (sql.got_data()) {
            return result;
        } else {
            m_log->warn("No tag record found for name '{}'", p_name);
            return {};
        }
        TRY_END()
        CATCH(database::SociError, {
            m_log->error(
                "Failed to retrieve tag for name '{}': {}", p_name, e.what());
        })
        return {};
    }

    const bool Analysis::analysis_tag_table_exists()
    {
        return database::Database::is_table_exists("analysis_tags");
    }

    void Analysis::analysis_tag_table_insert(
        const record::AnalysisTag &p_analysis_tag)
    {
        if (!analysis_tag_table_exists()) {
            m_log->error("Table for analysis_tags not found, cannot insert "
                         "record for analysis_id '{}', tag_id '{}'",
                         p_analysis_tag.analysis_id,
                         p_analysis_tag.tag_id);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO analysis_tags (analysis_id, tag_id) "
               "VALUES (:analysis_id, :tag_id)",
            soci::use(p_analysis_tag);

        m_log->info("Successfully inserted analysis_tag record for analysis_id "
                    "'{}', tag_id '{}'",
                    p_analysis_tag.analysis_id,
                    p_analysis_tag.tag_id);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to insert analysis_tag for analysis_id '{}', "
                         "tag_id '{}': {}",
                         p_analysis_tag.analysis_id,
                         p_analysis_tag.tag_id,
                         e.what());
        })
    }

    const std::vector<record::Tag> Analysis::
        analysis_tag_get_tags_by_analysis_id(const int p_analysis_id)
    {
        std::vector<record::Tag> results;

        if (!analysis_tag_table_exists()) {
            m_log->error("Table for analysis_tags not found, cannot retrieve "
                         "tags for analysis_id '{}'",
                         p_analysis_id);
            return results;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Tag> rs =
            (sql.prepare << "SELECT t.id, t.name, t.description "
                            "FROM tags t "
                            "JOIN analysis_tags at ON t.id = at.tag_id "
                            "WHERE at.analysis_id = :analysis_id",
             soci::use(p_analysis_id));

        results.assign(rs.begin(), rs.end());

        m_log->info("Successfully retrieved {} tags for analysis_id '{}'",
                    results.size(),
                    p_analysis_id);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve tags for analysis_id '{}': {}",
                         p_analysis_id,
                         e.what());
        })

        return results;
    }
} // namespace engine::focades::analysis