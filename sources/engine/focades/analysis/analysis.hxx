#pragma once

#include <LIEF/LIEF.hpp>
#include <engine/focades/analysis/binary/lief/art/art.hxx>
#include <engine/focades/analysis/binary/lief/dex/dex.hxx>
#include <engine/focades/analysis/binary/lief/elf/elf.hxx>
#include <engine/focades/analysis/binary/lief/macho/macho.hxx>
#include <engine/focades/analysis/binary/lief/pe/pe.hxx>
#include <engine/focades/analysis/database/database.hxx>
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

        [[nodiscard]] const database::record::Analysis analyze(const record::File &);
        void file_write(const record::File &);
        void file_read(record::File &);

        void _plugins() override;

        std::shared_ptr<focades::analysis::database::Database> database;

        std::shared_ptr<focades::analysis::metadata::Metadata> metadata;
        std::shared_ptr<focades::analysis::threats::av::clamav::Clamav> clamav;
        std::shared_ptr<focades::analysis::threats::yara::Yara> yara;

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