#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/database/database.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <netdb.h>
#include <stdint.h>

namespace engine::focades::analysis
{
    Analysis::Analysis()
        : metadata(std::make_shared<focades::analysis::metadata::Metadata>()),
          scan_av_clamav(
              std::make_shared<focades::analysis::scan::av::clamav::Clamav>()),
          scan_yara(std::make_shared<focades::analysis::scan::yara::Yara>())
    {
    }

    void Analysis::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<focades::analysis::Analysis>(
            "Analysis",
            "scan",
            sol::property(
                [](focades::analysis::Analysis &self)
                    -> focades::analysis::Analysis & { return self; }),
            sol::meta_function::index,
            [](focades::analysis::Analysis &self,
               const std::string &key,
               sol::this_state ts) {
                sol::state_view lua(ts);
                if (key == "clamav" && self.scan_av_clamav)
                    return sol::make_object(
                        lua, std::ref(self.scan_av_clamav->clamav));
                if (key == "yara" && self.scan_yara)
                    return sol::make_object(lua,
                                            std::ref(self.scan_yara->yara));
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

        scan_yara->setup(p_config);
        scan_av_clamav->setup(p_config);
    }

    void Analysis::load() const
    {
        TRY_BEGIN()
        m_log->info("Loading rules yara ...");
        scan_yara->load();

        m_log->info("Loading rules clamav ...");
        scan_av_clamav->load([&](unsigned int p_total_rules) {
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
                            analysis.last_update_date = analysis.creation_date =
                                p_dto->creation_date;
                        });

        TRY_BEGIN()
        analysis.is_malicious = [&]() -> bool {
            bool result = false;
            scan_yara->scan(
                p_file.content,
                [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                    if (p_dto->math_status ==
                        focades::analysis::scan::yara::type::Scan::match) {
                        result = true;
                    }
                });

            scan_av_clamav->scan(
                p_file.content,
                [&](focades::analysis::scan::av::clamav::record::DTO *p_dto) {
                    if (p_dto->math_status ==
                        security::av::clamav::type::Scan::virus)
                        result = true;
                });
            return result;
        }();
        TRY_END()
        CATCH(security::av::clamav::exception::Scan,
              throw exception::Scan(fmt::format(
                  "Error scan clamav from file '{}'", analysis.sha256)))
        CATCH(security::yara::exception::Scan,
              throw exception::Scan(fmt::format(
                  "Error scan yara from file '{}'", analysis.sha256)))

        analysis.is_packed = (analysis.file_entropy >= packed_entropy);
        analysis.file_size = p_file.content.size();
        analysis.file_path = filesystem::Filesystem::path;

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

    const bool Analysis::table_exists()
    {
        return database::Database::is_table_exists("analysis");
    }

    const std::vector<record::Analysis> Analysis::table_get_all()
    {
        std::vector<record::Analysis> results;

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        soci::rowset<record::Analysis> rs =
            (sql.prepare
             << "SELECT id, file_name, file_type, sha256, sha1, sha512, "
                "sha224, sha384, sha3_256, sha3_512, file_size, file_entropy, "
                "creation_date, last_update_date, file_path, is_malicious, "
                "is_packed, owner "
                "FROM analysis");

        results.assign(rs.begin(), rs.end());

        m_log->info("Successfully retrieved {} analysis records",
                    results.size());
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to retrieve analysis records: {}", e.what());
        });

        return results;
    }

    void Analysis::table_insert(const record::Analysis &p_analysis)
    {
        if (!Analysis::table_exists()) {
            m_log->error("Table for analysis not found, cannot insert record "
                         "for sha256 '{}'",
                         p_analysis.sha256);
            return;
        }

        TRY_BEGIN()
        database::Soci &sql = engine::database::Database::exec();
        sql << "INSERT INTO analysis ("
               "file_name, file_type, sha256, sha1, sha512, sha224, "
               "sha384, "
               "sha3_256, sha3_512, file_size, file_entropy, "
               "creation_date, "
               "last_update_date, file_path, is_malicious, is_packed, owner) "
               "VALUES (:file_name, :file_type, :sha256, :sha1, "
               ":sha512, :sha224, :sha384, "
               ":sha3_256, :sha3_512, :file_size, :file_entropy, "
               ":creation_date, "
               ":last_update_date, :file_path, :is_malicious, :is_packed, "
               ":owner)",
            soci::use(p_analysis);

        m_log->info("Successfully inserted analysis record for sha256 '{}'",
                    p_analysis.sha256);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to insert analysis for sha256 '{}': {}",
                         p_analysis.sha256,
                         e.what());
        });
    }

    void Analysis::table_update(const record::Analysis &p_analysis)
    {
        if (!Analysis::table_exists()) {
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
               "owner = :owner "
               "WHERE sha256 = :sha256",
            soci::use(p_analysis);
        TRY_END()
        CATCH(database::SociError, {
            m_log->error("Failed to update analysis for sha256 '{}': {}",
                         p_analysis.sha256,
                         e.what());
        });
    }

    const bool Analysis::table_exists_by_sha256(
        const record::Analysis &p_analysis)
    {
        if (!Analysis::table_exists()) {
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
        });

        return false;
    }

    const record::Analysis Analysis::table_get_by_id(const int p_id)
    {
        if (!Analysis::table_exists()) {
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
               "is_malicious, is_packed, owner "
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

    const record::Analysis Analysis::table_get_by_sha256(
        const std::string &p_sha256)
    {
        if (!Analysis::table_exists()) {
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
               "is_malicious, is_packed, owner "
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
} // namespace engine::focades::analysis
