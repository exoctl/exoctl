#pragma once

#include <engine/bridge/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/bridge/focades/analysis/scan/yara/yara.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_ANALYSIS API_PREFIX("analysis")

namespace engine::bridge::endpoints
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

      private:
        server::Server *m_server;
        mutable map::Map m_map;

        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_yara;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan_av_clamav;
        std::unique_ptr<engine::server::gateway::web::Web> m_web_scan;

        std::shared_ptr<focades::analysis::scan::av::clamav::Clamav>
            m_scan_av_clamav;
        std::shared_ptr<focades::analysis::scan::yara::Yara> m_scan_yara;

        void scan();
        void scan_yara();
        void scan_av_clamav();
    };
} // namespace engine::bridge::endpoints
