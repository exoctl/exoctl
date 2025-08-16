#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/database/database.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
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

        // analysis.is_malicious;
        // analysis.packed;

        analysis.file_size = p_file.content.size();
        analysis.file_path = filesystem::Filesystem::path;
        Analysis::file_write({analysis.sha512, p_file.content});
        Analysis::table_insert(analysis);

        return analysis;
    }

    void Analysis::file_write(const record::File &p_file)
    {
        filesystem::record::EnqueueTask task;
        task.file.content = p_file.content;
        task.file.filename = p_file.filename;
        if (!filesystem::Filesystem::is_exists(task.file)) {
            filesystem::Filesystem::enqueue_write(task);
        }
    }

    const bool Analysis::table_exists()
    {
        return database::Database::is_table_exists("analysis");
    }

    void Analysis::table_insert(const record::Analysis &p_analysis)
    {
        if (!Analysis::table_exists()) {
            m_log->error("Table for analysis not found, reanalyze '{}' the "
                         "file to save it in the database",
                         p_analysis.sha256);
            return;
        }
    }

    void Analysis::table_update(const record::Analysis &p_analysis)
    {
    }

    const record::Analysis Analysis::table_get_by_id(const int p_id)
    {
        return {};
    }

    const record::Analysis Analysis::table_get_by_sha256(
        const std::string &p_sha256)
    {
        return {};
    }
} // namespace engine::focades::analysis
