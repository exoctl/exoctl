#pragma once

#include <LIEF/LIEF.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <engine/focades/analysis/analysis.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

namespace engine::bridge::endpoints::analysis
{
    class Analysis : public interface::IEndpoint,
                     public interface::IPlugins<Analysis>
    {
      public:
        Analysis();
        ~Analysis() = default;

        void setup(server::Server &);
        void load() const override;
        void _plugins() override;
        size_t min_binary_size;
        
        private:
        server::Server *m_server;
        mutable map::Map m_map;
        focades::analysis::Analysis m_analysis;
        bool m_enable;

        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_yara;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_av_clamav;

        void scan();
        // void scan_yara();
        // void scan_av_clamav();
    };
} // namespace engine::bridge::endpoints::analysis
