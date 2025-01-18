#pragma once

#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>
#include <engine/server/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/server/focades/analysis/scan/yara/yara.hxx>
#include <engine/interfaces/igateway.hxx>
#include <memory>

#define BASE_ANALYSIS API_PREFIX "/analysis"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            class Analysis : public interface::IGateway
            {
              public:
                Analysis(Server &);
                ~Analysis();

                void load() const override;

              private:
                Server &SERVER_INSTANCE;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::WebSocket> m_socket_scan_yara;
                std::unique_ptr<gateway::WebSocket> m_socket_scan_av_clamav;
                std::unique_ptr<gateway::WebSocket> m_socket_scan;

                std::unique_ptr<focades::analysis::scan::Yara> m_scan_yara;
                std::unique_ptr<focades::analysis::scan::av::Clamav>
                    m_scan_av_clamav;

                void prepare();
                void scan();
                void scan_yara();
                void scan_av_clamav();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine