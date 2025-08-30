#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/endpoints/analysis/families/families.hxx>
#include <engine/bridge/endpoints/analysis/records/records.hxx>
#include <engine/bridge/endpoints/analysis/scan/scan.hxx>
#include <engine/bridge/endpoints/analysis/tags/tags.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>
#include <stdint.h>

namespace engine::bridge::endpoints::analysis
{
    Analysis::Analysis()
        : min_binary_size(0), map_(BASE_ANALYSIS), enable_(true)
    {
    }

    void Analysis::_plugins()
    {
        plugins::Plugins::lua.state
            .new_usertype<bridge::endpoints::analysis::Analysis>(
                "EndpointAnalysis",
                "analysis",
                &bridge::endpoints::analysis::Analysis::analysis);

        focades::analysis::Analysis::plugins();
    }

    void Analysis::setup(server::Server &p_server)
    {
        server_ = &p_server;
        enable_ = server_->config->get("bridge.endpoint.analysis.enable")
                      .value<bool>()
                      .value();

        if (!enable_) {
            server_->log->warn("Gateway 'Analysis' not enabled");
            return;
        }
        analysis.setup(*server_->config, *server_->log);

        min_binary_size =
            server_->config
                ->get("bridge.endpoint.analysis.scan.min_binary_size")
                .value<size_t>()
                .value();

        Scan::setup(*this);
        Records::setup(*this);
        Families::setup(*this);
        Tags::setup(*this);
    }

    void Analysis::load() const
    {
        if (enable_) {
            analysis.load();
            map_.get_routes(
                [&](const std::string p_route) { map_.call_route(p_route); });
        }
    }
} // namespace engine::bridge::endpoints::analysis