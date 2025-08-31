#include "exception.hxx"
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
        analysis.description = (analysis.is_malicious)
                                   ? "File detected as malicious"
                                   : "File not detected as malicious";

        analysis.family_id = [&]() -> int {
            int best_family = 0;

            for (const auto &anal : database->analysis_table_get_all()) {
                if (anal.file_type != analysis.file_type ||
                    anal.sha256 == analysis.sha256) {
                    continue;
                }

                int dist = crypto::Tlsh::compare(anal.tlsh, analysis.tlsh);
                if (dist <= family_tlsh_threshold) {
                    family_tlsh_threshold = dist;
                    best_family = anal.family_id;
                    if (dist == 0) {
                        break;
                    }
                }
            }

            return best_family;
        }();

        return analysis;
    }

    void Analysis::save_analyze(const record::File &p_file,
                                const database::record::Analysis &p_analysis)
    {
        filesystem::record::EnqueueTask task;
        task.file.content.assign(p_file.content);
        task.file.filename.assign(p_file.filename);

        (!filesystem::Filesystem::is_exists(task.file))
            ? filesystem::Filesystem::enqueue_write(task)
            : (void) 0;

        (database->analysis_table_exists_by_sha256(p_analysis.sha256))
            ? database->analysis_table_update(p_analysis)
            : database->analysis_table_insert(p_analysis);
    }

    void Analysis::read_analyze(record::File &p_file,
                                database::record::Analysis &p_analysis)
    {
        filesystem::record::File file;
        file.filename.assign(p_file.filename);

        if (!filesystem::Filesystem::is_exists(file)) {
            log_->warn("File with sha256 '{}' does not exist, cannot read",
                       p_file.filename);
        } else {
            filesystem::Filesystem::read(file);
            p_file.content.assign(file.content);
        }

        p_analysis = database->analysis_table_get_by_sha256(file.filename);
    }

    void Analysis::update_analyze(database::record::Analysis &p_analysis,
                                  database::record::Analysis &p_new_analysis)
    {
        p_new_analysis.id = p_analysis.id;
        p_new_analysis.file_name = p_new_analysis.file_name.size() > 0
                                       ? p_new_analysis.file_name
                                       : p_analysis.file_name;
        p_new_analysis.family_id = (p_new_analysis.family_id) > 0
                                       ? p_new_analysis.family_id
                                       : p_analysis.family_id;
        p_new_analysis.description = (p_new_analysis.description.size() > 0)
                                         ? p_new_analysis.description
                                         : p_analysis.description;
        p_new_analysis.owner = p_analysis.owner;

        (database->analysis_table_exists_by_sha256(p_analysis.sha256))
            ? database->analysis_table_update(p_new_analysis)
            : database->analysis_table_insert(p_new_analysis);
    }

    void Analysis::remove_analyze(const database::record::Analysis &p_analysis)
    {
        filesystem::record::File file;
        file.filename.assign(p_analysis.sha256);

        if (!filesystem::Filesystem::is_exists(file)) {
            log_->warn("File with sha256 '{}' does not exist, cannot delete",
                       p_analysis.sha256);
        } else {
            filesystem::Filesystem::remove(file);
        }

        if (!database->analysis_table_exists_by_sha256(p_analysis.sha256)) {
            log_->warn(
                "Analysis with sha256 '{}' does not exist, cannot delete",
                p_analysis.sha256);
        } else {
            database->analysis_table_delete(p_analysis);
        }
    }

    void Analysis::save_tags(const database::record::Tag &p_tag)
    {
        if (database->tag_table_exists_by_name(p_tag.name)) {
            log_->warn("Tag with name '{}' already exists, skipping creation",
                       p_tag.name);
            throw exception::TagExists("Tag already exists");
        }

        database->tag_table_insert(p_tag);
    }

    void Analysis::update_tags(database::record::Tag &p_tag)
    {
        if (!database->tag_table_exists_by_id(p_tag.id)) {
            log_->warn("Tag with ID '{}' does not exist, cannot update",
                       p_tag.id);
            throw exception::TagNotFound("Tag does not exist");
        }

        database->tag_table_update(p_tag);
    }

    void Analysis::remove_tags(const database::record::Tag &p_tag)
    {
        if (!database->tag_table_exists_by_id(p_tag.id)) {
            log_->warn("Tag with ID '{}' does not exist, cannot delete",
                       p_tag.id);
            throw exception::TagNotFound("Tag does not exist");
        }

        database->tag_table_delete(p_tag);
    }

    void Analysis::save_families(const database::record::Family &p_family)
    {
        if (database->family_table_exists_by_name(p_family.name)) {
            log_->warn(
                "Family with name '{}' already exists, skipping creation",
                p_family.name);
            throw exception::FamilyExists("Family already exists");
        }

        database->family_table_insert(p_family);
    }

    void Analysis::update_families(database::record::Family &p_family)
    {
        if (!database->family_table_exists_by_id(p_family.id)) {
            log_->warn("Family with ID '{}' does not exist, cannot update",
                       p_family.id);
            throw exception::FamilyNotFound("Family does not exist");
        }

        database->family_table_update(p_family);
    }

    void Analysis::remove_families(const database::record::Family &p_family)
    {
        if (!database->family_table_exists_by_id(p_family.id)) {
            log_->warn("Family with ID '{}' does not exist, cannot delete",
                       p_family.id);
            throw exception::FamilyNotFound("Family does not exist");
        }

        database->family_table_delete(p_family);
    }

} // namespace engine::focades::analysis