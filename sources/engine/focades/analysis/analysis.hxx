#pragma once

#include "entitys.hxx"
#include <LIEF/LIEF.hpp>
#include <engine/focades/analysis/binary/lief/art/art.hxx>
#include <engine/focades/analysis/binary/lief/dex/dex.hxx>
#include <engine/focades/analysis/binary/lief/elf/elf.hxx>
#include <engine/focades/analysis/binary/lief/macho/macho.hxx>
#include <engine/focades/analysis/binary/lief/pe/pe.hxx>
#include <engine/focades/analysis/entitys.hxx>
#include <engine/focades/analysis/metadata/metadata.hxx>
#include <engine/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/focades/analysis/scan/yara/yara.hxx>
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
        const record::Analysis scan(const record::File &);

        [[nodiscard]] const bool table_exists();
        void table_insert(const record::Analysis &);
        void table_update(const record::Analysis &);
        [[nodiscard]] const std::vector<record::Analysis> table_get_all();
        [[nodiscard]] const record::Analysis table_get_by_id(const int);
        [[nodiscard]] const record::Analysis table_get_by_sha256(
            const std::string &);
        [[nodiscard]] const bool table_exists_by_sha256(
            const record::Analysis &);
        void file_write(const record::File &);
        void file_read(record::File &);

        void _plugins() override;

        std::shared_ptr<focades::analysis::metadata::Metadata> metadata;

        // scan binary
        std::shared_ptr<focades::analysis::scan::av::clamav::Clamav>
            scan_av_clamav;
        std::shared_ptr<focades::analysis::scan::yara::Yara> scan_yara;

        // parser binary formats
        std::shared_ptr<focades::analysis::binary::pe::PE> binary_pe;
        std::shared_ptr<focades::analysis::binary::macho::MACHO> binary_macho;
        std::shared_ptr<focades::analysis::binary::dex::DEX> binary_dex;
        std::shared_ptr<focades::analysis::binary::art::ART> binary_art;
        std::shared_ptr<focades::analysis::binary::elf::ELF> binary_elf;

        double packed_entropy;

      private:
        logging::Logging *m_log;
        configuration::Configuration *m_config;
    };
} // namespace engine::focades::analysis