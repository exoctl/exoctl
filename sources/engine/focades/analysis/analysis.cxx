#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/crypto/tlsh.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <fmt/format.h>

namespace engine::focades::analysis
{
    Analysis::Analysis()
        : metadata(std::make_shared<focades::analysis::metadata::Metadata>()),
          clamav(std::make_shared<
                 focades::analysis::threats::av::clamav::Clamav>()),
          yara(std::make_shared<focades::analysis::threats::yara::Yara>()),
          database(std::make_shared<focades::analysis::database::Database>())
    {
    }

    void Analysis::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<focades::analysis::Analysis>(
            "Analysis",
            "yara_rules_path",
            sol::property(
                [](focades::analysis::Analysis &self) -> const std::string {
                    return (self.yara) ? self.yara->rules_path : "";
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
        config_ = &p_config;
        log_ = &p_log;

        packed_entropy_threshold =
            config_->get("focades.analysis.packed.entropy.threshold")
                .value<double>()
                .value();
        family_tlsh_threshold =
            config_->get("focades.analysis.family.tlsh.threshold")
                .value<int>()
                .value();

        database->setup(p_config, p_log);
        yara->setup(p_config);
        clamav->setup(p_config);
    }

    void Analysis::load() const
    {
        TRY_BEGIN()
        log_->info("Loading rules yara ...");
        yara->load();

        log_->info("Loading rules clamav ...");
        clamav->load([&](unsigned int p_total_rules) {
            log_->info(
                "Successfully loaded rules. Total Clamav rules count: {:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            log_->error("{}", e.what());
            throw exception::Load(e.what());
        })
    }

    const database::record::Analysis Analysis::analyze(
        const record::File &p_file)
    {
        database::record::Analysis analysis;
        
        analysis.owner = p_file.owner;

        metadata->parse(p_file.content, [&](metadata::record::DTO *p_dto) {
            analysis.file_name = p_dto->sha256;
            analysis.sha256 = p_dto->sha256;
            analysis.sha1 = p_dto->sha1;
            analysis.sha512 = p_dto->sha512;
            analysis.sha224 = p_dto->sha224;
            analysis.sha384 = p_dto->sha384;
            analysis.sha3_256 = p_dto->sha3_256;
            analysis.sha3_512 = p_dto->sha3_512;
            analysis.file_type = p_dto->mime_type;
            analysis.file_entropy = p_dto->entropy;
            analysis.tlsh = p_dto->tlsh;
            analysis.creation_date = p_dto->creation_date;
            analysis.last_update_date = p_dto->creation_date;
        });

        TRY_BEGIN()
        bool malicious = false;

        yara->scan(p_file.content, [&](threats::yara::record::DTO *p_dto) {
            if (p_dto->math_status == threats::yara::type::Scan::match)
                malicious = true;
        });

        clamav->scan(p_file.content,
                     [&](threats::av::clamav::record::DTO *p_dto) {
                         if (p_dto->math_status ==
                             security::av::clamav::type::Scan::virus)
                             malicious = true;
                     });

        analysis.is_malicious = malicious;
        TRY_END()
        CATCH(security::av::clamav::exception::Scan, {
            throw exception::Scan(fmt::format(
                "Error scan clamav from file '{}'", analysis.sha256));
        })
        CATCH(security::yara::exception::Scan, {
            throw exception::Scan(
                fmt::format("Error scan yara from file '{}'", analysis.sha256));
        })

        analysis.is_packed =
            (analysis.file_entropy >= packed_entropy_threshold);
        analysis.file_size = p_file.content.size();
        analysis.file_path = filesystem::Filesystem::path;
        analysis.description = analysis.is_malicious
                                   ? "File detected as malicious"
                                   : "File not detected as malicious";

        const auto &all_analysis = database->analysis_table_get_all();
        int best_family = 0;
        int best_dist = std::numeric_limits<int>::max();

        for (const auto &anal : all_analysis) {
            if (anal.file_type != analysis.file_type ||
                anal.sha256 == analysis.sha256)
                continue;

            int dist = crypto::Tlsh::compare(anal.tlsh, analysis.tlsh);
            if (dist < best_dist && dist <= family_tlsh_threshold) {
                best_dist = dist;
                best_family = anal.family_id;
                if (dist == 0)
                    break;
            }
        }
        analysis.family_id = best_family;

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

    void Analysis::file_remove(const record::File &p_file)
    {
        filesystem::record::File file;
        file.filename.assign(p_file.filename);
        if (filesystem::Filesystem::is_exists(file)) {
            filesystem::Filesystem::remove(file);
        }
    }
} // namespace engine::focades::analysis