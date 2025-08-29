#include <engine/database/database.hxx>
#include <engine/focades/analysis/database/database.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <fmt/format.h>

namespace engine::focades::analysis::database
{
    void Database::setup(configuration::Configuration &p_config,
                         logging::Logging &p_log)
    {
        config_ = &p_config;
        log_ = &p_log;
    }

    const bool Database::analysis_table_exists()
    {
        return engine::database::Database::is_table_exists("analysis");
    }

    const std::vector<record::Analysis> Database::analysis_table_get_all()
    {
        std::vector<record::Analysis> results;

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Analysis> rs =
            (sql.prepare
             << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
                "sha224, sha384, sha3_256, sha3_512, file_size, "
                "file_entropy, creation_date, last_update_date, file_path, "
                "is_malicious, is_packed, owner, family_id, tlsh, description "
                "FROM analysis");

        results.assign(rs.begin(), rs.end());

        log_->info("Successfully retrieved {} analysis records",
                   results.size());
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to retrieve analysis records: {}", e.what());
        })

        return results;
    }

    void Database::analysis_table_insert(const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, cannot insert "
                        "record for sha256 '{}'",
                        p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
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

        log_->info("Successfully inserted analysis record for sha256 '{}'",
                   p_analysis.sha256);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to insert analysis for sha256 '{}': {}",
                        p_analysis.sha256,
                        e.what());
        })
    }

    void Database::analysis_table_update(const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, reanalyze '{}' "
                        "the file to save it in the database",
                        p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "UPDATE analysis SET "
               "file_name = :file_name, file_type = :file_type, sha1 = :sha1, "
               "sha512 = :sha512, sha224 = :sha224, sha384 = :sha384, "
               "sha3_256 = :sha3_256, sha3_512 = :sha3_512, file_size = "
               ":file_size, "
               "file_entropy = :file_entropy, last_update_date = "
               ":last_update_date, "
               "file_path = :file_path, is_malicious = :is_malicious, "
               "is_packed = :is_packed, "
               "owner = :owner, tlsh = :tlsh, family_id = :family_id, "
               "description = :description "
               "WHERE sha256 = :sha256",
            soci::use(p_analysis);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to update analysis for sha256 '{}': {}",
                        p_analysis.sha256,
                        e.what());
        })
    }

    void Database::analysis_table_delete(const record::Analysis &p_analysis)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, cannot delete "
                        "record with SHA256 '{}'",
                        p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "DELETE FROM analysis WHERE sha256 = :sha256",
            soci::use(p_analysis.sha256);

        log_->info("Successfully deleted analysis record for SHA256 '{}'",
                   p_analysis.sha256);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to delete analysis for SHA256 '{}': {}",
                        p_analysis.sha256,
                        e.what());
        })
    }

    const bool Database::analysis_table_exists_by_sha256(
        const std::string &p_sha256)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, cannot check "
                        "existence for SHA256 '{}'",
                        p_sha256);
            return false;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        int exists;
        sql << "SELECT EXISTS (SELECT 1 FROM analysis WHERE sha256 = :sha256)",
            soci::use(p_sha256), soci::into(exists);

        if (sql.got_data()) {
            return exists != 0;
        } else {
            log_->warn(
                "No result returned when checking existence for SHA256 '{}'",
                p_sha256);
            return false;
        }
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to check existence for SHA256 '{}': {}",
                        p_sha256,
                        e.what());
        })

        return false;
    }

    const record::Analysis Database::analysis_table_get_by_id(const int p_id)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, cannot "
                        "retrieve record with ID '{}'",
                        p_id);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Analysis result;
        sql << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
               "sha224, sha384, sha3_256, sha3_512, file_size, "
               "file_entropy, creation_date, last_update_date, file_path, "
               "is_malicious, is_packed, owner, family_id, tlsh, description "
               "FROM analysis WHERE id = :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No analysis record found for ID '{}'", p_id);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to retrieve analysis for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Analysis Database::analysis_table_get_by_sha256(
        const std::string &p_sha256)
    {
        if (!analysis_table_exists()) {
            log_->error("Table for analysis not found, cannot "
                        "retrieve record with SHA256 '{}'",
                        p_sha256);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Analysis result;
        sql << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
               "sha224, sha384, sha3_256, sha3_512, file_size, "
               "file_entropy, creation_date, last_update_date, file_path, "
               "is_malicious, is_packed, owner, family_id, tlsh, description "
               "FROM analysis WHERE sha256 = :sha256",
            soci::use(p_sha256), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No analysis record found for SHA256 '{}'", p_sha256);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to retrieve analysis for SHA256 '{}': {}",
                        p_sha256,
                        e.what());
        })
        return {};
    }

    void Database::family_table_delete(const record::Family &p_family)
    {
        if (!family_table_exists()) {
            log_->error("Table for family not found, cannot delete "
                        "record with ID '{}'",
                        p_family.id);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        int count;
        sql << "SELECT COUNT(*) FROM analysis WHERE family_id = :id",
            soci::use(p_family.id), soci::into(count);
        if (sql.got_data() && count > 0) {
            log_->error("Cannot delete family ID '{}' as it is referenced by "
                        "{} analysis records",
                        p_family.id,
                        count);
            return;
        }

        sql << "DELETE FROM family WHERE id = :id", soci::use(p_family.id);

        log_->info("Successfully deleted family record for ID '{}'", p_family.id);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to delete family for ID '{}': {}", p_family.id, e.what());
        })
    }

    const bool Database::family_table_exists()
    {
        return engine::database::Database::is_table_exists("family");
    }

    void Database::family_table_insert(const record::Family &p_family)
    {
        if (!family_table_exists()) {
            log_->error("Table for family not found, cannot insert "
                        "record for name '{}'",
                        p_family.name);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO family (name, description) VALUES (:name, "
               ":description)",
            soci::use(p_family);

        log_->info("Successfully inserted family record for name '{}'",
                   p_family.name);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to insert family for name '{}': {}",
                        p_family.name,
                        e.what());
        })
    }

    const std::vector<record::Family> Database::family_table_get_all()
    {
        std::vector<record::Family> results;

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Family> rs =
            (sql.prepare << "SELECT id, name, description FROM family");

        results.assign(rs.begin(), rs.end());

        log_->info("Successfully retrieved {} family records", results.size());
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to retrieve family records: {}", e.what());
        })

        return results;
    }

    const record::Family Database::family_table_get_by_id(const int p_id)
    {
        if (!family_table_exists()) {
            log_->error("Table for family not found, cannot retrieve "
                        "record with ID '{}'",
                        p_id);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Family result;
        sql << "SELECT id, name, description FROM family WHERE id = :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No family record found for ID '{}'", p_id);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to retrieve family for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Family Database::family_table_get_by_name(
        const std::string &p_name)
    {
        if (!family_table_exists()) {
            log_->error("Table for family not found, cannot retrieve "
                        "record with name '{}'",
                        p_name);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Family result;
        sql << "SELECT id, name, description FROM family WHERE name = :name",
            soci::use(p_name), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No family record found for name '{}'", p_name);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to retrieve family for name '{}': {}",
                        p_name,
                        e.what());
        })
        return {};
    }

    void Database::tag_table_delete(const record::Tag &p_tag)
    {
        if (!tag_table_exists()) {
            log_->error("Table for tags not found, cannot delete "
                        "record with ID '{}'",
                        p_tag.id);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        int count;
        sql << "SELECT COUNT(*) FROM analysis_tags WHERE tag_id = :id",
            soci::use(p_tag.id), soci::into(count);
        if (sql.got_data() && count > 0) {
            log_->error("Cannot delete tag ID '{}' as it is referenced by {} "
                        "analysis_tags",
                        p_tag.id,
                        count);
            return;
        }

        sql << "DELETE FROM tags WHERE id = :id", soci::use(p_tag.id);

        log_->info("Successfully deleted tag record for ID '{}'", p_tag.id);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to delete tag for ID '{}': {}", p_tag.id, e.what());
        })
    }

    const bool Database::tag_table_exists()
    {
        return engine::database::Database::is_table_exists("tags");
    }

    void Database::tag_table_insert(const record::Tag &p_tag)
    {
        if (!tag_table_exists()) {
            log_->error(
                "Table for tags not found, cannot insert record for name '{}'",
                p_tag.name);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO tags (name, description) VALUES (:name, "
               ":description)",
            soci::use(p_tag);

        log_->info("Successfully inserted tag record for name '{}'",
                   p_tag.name);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to insert tag for name '{}': {}", p_tag.name, e.what());
        })
    }

    void Database::tag_table_update(const record::Tag &p_tag)
    {
        if (!tag_table_exists()) {
            log_->error(
                "Table for tags not found, cannot insert record for name '{}'",
                p_tag.name);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "UPDATE tags SET name = :name, description = :description WHERE "
               "id = :id",
            soci::use(p_tag);

        log_->info("Successfully update tag record for name '{}'", p_tag.name);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to update tag for name '{}': {}", p_tag.name, e.what());
        })
    }

    const std::vector<record::Tag> Database::tag_table_get_all()
    {
        std::vector<record::Tag> results;

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Tag> rs =
            (sql.prepare << "SELECT id, name, description FROM tags");

        results.assign(rs.begin(), rs.end());

        log_->info("Successfully retrieved {} tag records", results.size());
        TRY_END()
        CATCH(engine::database::SociError,
              { log_->error("Failed to retrieve tag records: {}", e.what()); })

        return results;
    }

    const record::Tag Database::tag_table_get_by_id(const int p_id)
    {
        if (!tag_table_exists()) {
            log_->error(
                "Table for tags not found, cannot retrieve record with ID '{}'",
                p_id);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Tag result;
        sql << "SELECT id, name, description FROM tags WHERE id = :id",
            soci::use(p_id), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No tag record found for ID '{}'", p_id);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to retrieve tag for ID '{}': {}", p_id, e.what());
        })
        return {};
    }

    const record::Tag Database::tag_table_get_by_name(const std::string &p_name)
    {
        if (!tag_table_exists()) {
            log_->error("Table for tags not found, cannot retrieve "
                        "record with name '{}'",
                        p_name);
            return {};
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        record::Tag result;
        sql << "SELECT id, name, description FROM tags WHERE name = :name",
            soci::use(p_name), soci::into(result);

        if (sql.got_data())
            return result;

        log_->warn("No tag record found for name '{}'", p_name);
        return {};

        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error(
                "Failed to retrieve tag for name '{}': {}", p_name, e.what());
        })
        return {};
    }

    void Database::analysis_tag_table_delete(const int p_analysis_id,
                                             const int p_tag_id)
    {
        if (!analysis_tag_table_exists()) {
            log_->error(
                "Table for analysis_tags not found, cannot delete record for "
                "analysis_id '{}', tag_id '{}'",
                p_analysis_id,
                p_tag_id);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "DELETE FROM analysis_tags WHERE analysis_id = :analysis_id AND "
               "tag_id = :tag_id",
            soci::use(p_analysis_id), soci::use(p_tag_id);

        log_->info("Successfully deleted analysis_tag record for analysis_id "
                   "'{}', tag_id '{}'",
                   p_analysis_id,
                   p_tag_id);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to delete analysis_tag for analysis_id '{}', "
                        "tag_id '{}': {}",
                        p_analysis_id,
                        p_tag_id,
                        e.what());
        })
    }

    const bool Database::analysis_tag_table_exists()
    {
        return engine::database::Database::is_table_exists("analysis_tags");
    }

    void Database::analysis_tag_table_insert(
        const record::AnalysisTag &p_analysis_tag)
    {
        if (!analysis_tag_table_exists()) {
            log_->error(
                "Table for analysis_tags not found, cannot insert record for "
                "analysis_id '{}', tag_id '{}'",
                p_analysis_tag.analysis_id,
                p_analysis_tag.tag_id);
            return;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO analysis_tags (analysis_id, tag_id) VALUES "
               "(:analysis_id, :tag_id)",
            soci::use(p_analysis_tag);

        log_->info("Successfully inserted analysis_tag record for "
                   "analysis_id '{}', tag_id '{}'",
                   p_analysis_tag.analysis_id,
                   p_analysis_tag.tag_id);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to insert analysis_tag for "
                        "analysis_id '{}', tag_id '{}': {}",
                        p_analysis_tag.analysis_id,
                        p_analysis_tag.tag_id,
                        e.what());
        })
    }

    const std::vector<record::Tag> Database::
        analysis_tag_get_tags_by_analysis_id(const int p_analysis_id)
    {
        std::vector<record::Tag> results;

        if (!analysis_tag_table_exists()) {
            log_->error("Table for analysis_tags not found, cannot "
                        "retrieve tags for analysis_id '{}'",
                        p_analysis_id);
            return results;
        }

        TRY_BEGIN()
        engine::database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Tag> rs =
            (sql.prepare
                 << "SELECT t.id, t.name, t.description "
                    "FROM tags t JOIN analysis_tags at ON t.id = at.tag_id "
                    "WHERE at.analysis_id = :analysis_id",
             soci::use(p_analysis_id));

        results.assign(rs.begin(), rs.end());

        log_->info("Successfully retrieved {} tags for analysis_id '{}'",
                   results.size(),
                   p_analysis_id);
        TRY_END()
        CATCH(engine::database::SociError, {
            log_->error("Failed to retrieve tags for analysis_id '{}': {}",
                        p_analysis_id,
                        e.what());
        })

        return results;
    }
} // namespace engine::focades::analysis::database