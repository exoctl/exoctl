#pragma once

#include <engine/crowapp/bridge/gateway/map/map.hxx>
#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>
#include <engine/crowapp/focades/analysis/scan/yara/yara.hxx>
#include <engine/crowapp/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/interfaces/igateway.hxx>
#include <memory>
#include <engine/crowapp/crowapp.hxx>

#define BASE_ANALYSIS API_PREFIX "/analysis"

namespace crowapp
{
    namespace bridge
    {
        class Analysis : public interface::IGateway
        {
          public:
            Analysis(CrowApp &);
            ~Analysis();

            void load() const override;

          private:
            CrowApp &m_crowapp;
            mutable gateway::Map m_map;

            std::unique_ptr<gateway::WebSocket> m_socket_scan_yara;
            std::unique_ptr<gateway::WebSocket> m_socket_scan_av_clamav;

            std::unique_ptr<focades::analysis::scan::Yara> m_scan_yara;
            std::unique_ptr<focades::analysis::scan::av::Clamav> m_scan_clamav;

            void prepare();
            void scan_yara();
            void scan_av_clamav();
        };
    } // namespace bridge
} // namespace crowapp