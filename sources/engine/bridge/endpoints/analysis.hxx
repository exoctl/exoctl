#pragma once

#include <engine/bridge/focades/analysis/scan/av/clamav/clamav.hxx>
#include <engine/bridge/focades/analysis/scan/yara/yara.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/map/map.hxx>
#include <engine/server/gateway/websocket/websocket.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_ANALYSIS API_PREFIX "/analysis"

namespace engine::bridge::endpoints
{
    class Analysis : public interface::IEndpoint
#ifdef ENGINE_PRO
        ,
                     public interface::IPlugins
#endif
    {
      public:
        Analysis(server::Server &);
        ~Analysis() = default;

        void load() const override;
        void register_plugins() override;

      private:
        server::Server &m_server;
        mutable engine::server::gateway::Map m_map;

        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_scan_yara;
        std::unique_ptr<engine::server::gateway::WebSocket>
            m_socket_scan_av_clamav;
        std::unique_ptr<engine::server::gateway::WebSocket> m_socket_scan;

        std::unique_ptr<focades::analysis::scan::yara::Yara> m_scan_yara;
        std::unique_ptr<focades::analysis::scan::av::clamav::Clamav>
            m_scan_av_clamav;

        void prepare();
        void scan();
        void scan_yara();
        void scan_av_clamav();
    };
} // namespace engine::bridge::endpoints
