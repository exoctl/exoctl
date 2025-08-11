#pragma once

#include <LIEF/LIEF.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
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
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

#define BASE_ANALYSIS API_PREFIX("analysis")

namespace engine::focades::analysis
{
    class Analysis : public interface::IPlugins<Analysis>
    {
      public:
        Analysis();
        ~Analysis();

        void setup(configuration::Configuration &, logging::Logging &);
        void load() const;
        void enqueue_scan(record::EnqueueTask &);
        void _plugins() override;

        std::atomic<bool> is_running;
        std::atomic<size_t> scan_queue_size;
        size_t max_queue_size;

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

      private:
        logging::Logging *m_log;
        configuration::Configuration *m_config;
        std::queue<record::EnqueueTask> m_scan_queue;
        std::mutex m_scan_mutex;
        std::condition_variable m_scan_cv;
        std::thread m_scan_worker;
        std::atomic<int> m_id_counter;

        void worker();
    };
} // namespace engine::bridge::endpoints::analysis
