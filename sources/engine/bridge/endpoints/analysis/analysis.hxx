#pragma once

#include <LIEF/LIEF.hpp>
#include <engine/bridge/focades/analysis/binary/lief/art/art.hxx>
#include <engine/bridge/focades/analysis/binary/lief/dex/dex.hxx>
#include <engine/bridge/focades/analysis/binary/lief/elf/elf.hxx>
#include <engine/bridge/focades/analysis/binary/lief/macho/macho.hxx>
#include <engine/bridge/focades/analysis/binary/lief/pe/pe.hxx>
#include <engine/bridge/focades/analysis/metadata/metadata.hxx>
#include <engine/bridge/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/bridge/focades/analysis/scan/yara/yara.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <chrono>
#include <atomic>

#define BASE_ANALYSIS API_PREFIX("analysis")

namespace engine::bridge::endpoints
{
    class Analysis : public interface::IEndpoint,
                     public interface::IPlugins<Analysis>
    {
      public:
        Analysis();
        ~Analysis();

        void setup(server::Server &);
        void load() const override;
        void enqueue_scan(const std::string &);
        void _plugins() override;

        std::atomic<bool> is_running;
        std::atomic<size_t> scan_queue_size;
        size_t max_queue_size;

      private:
        server::Server *m_server;
        mutable map::Map m_map;
        
        std::queue<std::string> m_scan_queue;
        std::mutex m_scan_mutex;
        std::condition_variable m_scan_cv;
        std::thread m_scan_worker;

        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_yara;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_av_clamav;

        std::shared_ptr<focades::analysis::scan::av::clamav::Clamav>
            m_scan_av_clamav;
        std::shared_ptr<focades::analysis::scan::yara::Yara> m_scan_yara;
        std::shared_ptr<focades::analysis::metadata::Metadata> m_metadata;
        std::shared_ptr<focades::analysis::binary::pe::PE> m_binary_pe;
        std::shared_ptr<focades::analysis::binary::macho::MACHO> m_binary_macho;
        std::shared_ptr<focades::analysis::binary::dex::DEX> m_binary_dex;
        std::shared_ptr<focades::analysis::binary::art::ART> m_binary_art;
        std::shared_ptr<focades::analysis::binary::elf::ELF> m_binary_elf;
      
        void worker();
        void scan();
        void scan_yara();
        void scan_av_clamav();
    };
} // namespace engine::bridge::endpoints
