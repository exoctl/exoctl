#pragma once

#include <LIEF/LIEF.hpp>
#include <engine/focades/analysis/binary/lief/art/art.hxx>
#include <engine/focades/analysis/binary/lief/dex/dex.hxx>
#include <engine/focades/analysis/binary/lief/elf/elf.hxx>
#include <engine/focades/analysis/binary/lief/macho/macho.hxx>
#include <engine/focades/analysis/binary/lief/pe/pe.hxx>
#include <engine/focades/analysis/entitys.hxx>
#include <engine/focades/analysis/metadata/metadata.hxx>
#include <engine/focades/analysis/threats/av/clamav/clamav.hxx>
#include <engine/focades/analysis/threats/yara/yara.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/logging/logging.hxx>

#define BASE_ANALYSIS API_PREFIX("analysis")

namespace engine::focades::analysis
{
    class Analysis : public interface::IPlugins<Analysis>
    {
      public:
        Analysis();
        ~Analysis() = default;

        void setup(configuration::Configuration &, logging::Logging &);
        void load() const;

        [[nodiscard]] const record::Analysis scan(const record::File &);
        void file_write(const record::File &);
        void file_read(record::File &);
        [[nodiscard]] const bool analysis_table_exists();
        [[nodiscard]] const std::vector<record::Analysis> analysis_table_get_all();
        void analysis_table_insert(const record::Analysis &);
        void analysis_table_update(const record::Analysis &);
        [[nodiscard]] const bool analysis_table_exists_by_sha256(
            const record::Analysis &);
        const record::Analysis analysis_table_get_by_id(const int);
        const record::Analysis analysis_table_get_by_sha256(const std::string &);

        [[nodiscard]] const bool family_table_exists();
        void family_table_insert(const record::Family &);
        [[nodiscard]] const std::vector<record::Family> family_table_get_all();
        [[nodiscard]] const record::Family family_table_get_by_id(const int);
        [[nodiscard]] const record::Family family_table_get_by_name(
            const std::string &);

        [[nodiscard]] const bool tag_table_exists();
        void tag_table_insert(const record::Tag &);
        [[nodiscard]] const std::vector<record::Tag> tag_table_get_all();
        [[nodiscard]] const record::Tag tag_table_get_by_id(const int p_id);
        [[nodiscard]] const record::Tag tag_table_get_by_name(
            const std::string &);

        [[nodiscard]] const bool analysis_tag_table_exists();
        void analysis_tag_table_insert(const record::AnalysisTag &);
        [[nodiscard]] const std::vector<record::Tag>
        analysis_tag_get_tags_by_analysis_id(const int);

        void _plugins() override;

        std::shared_ptr<focades::analysis::metadata::Metadata> metadata;

        // scan binary
        std::shared_ptr<focades::analysis::threats::av::clamav::Clamav> clamav;
        std::shared_ptr<focades::analysis::threats::yara::Yara> yara;

        // parser binary formats
        std::shared_ptr<focades::analysis::binary::pe::PE> pe;
        std::shared_ptr<focades::analysis::binary::macho::MACHO> macho;
        std::shared_ptr<focades::analysis::binary::dex::DEX> dex;
        std::shared_ptr<focades::analysis::binary::art::ART> art;
        std::shared_ptr<focades::analysis::binary::elf::ELF> elf;

        double packed_entropy_threshold;
        int family_tlsh_threshold;

      private:
        logging::Logging *log_;
        configuration::Configuration *config_;
    };
} // namespace engine::focades::analysis