#pragma once

#include <LIEF/LIEF.hpp>
#include <engine/bridge/map/map.hxx>
#include <engine/focades/analysis/analysis.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>

#define BASE_ANALYSIS API_PREFIX("analysis")

namespace engine::bridge::endpoints::analysis
{
    class Scan;
    class Records;
    class Update;
    class Families;
    class Tags;

    class Analysis : public interface::IEndpoint,
                     public interface::IPlugins<Analysis>
    {
        friend class Scan;
        friend class Records;
        friend class Families;
        friend class Tags;

      public:
        Analysis();
        ~Analysis() = default;

        void setup(server::Server &);
        void load() const override;
        void _plugins() override;
        size_t min_binary_size;
        focades::analysis::Analysis analysis;

      private:
        server::Server *server_;
        mutable map::Map map_;
        bool enable_;

        std::unique_ptr<engine::server::gateway::web::Web> web_scan_;
        std::unique_ptr<engine::server::gateway::web::Web> web_scan_threats_;
        std::unique_ptr<engine::server::gateway::web::Web> web_records_;
        std::unique_ptr<engine::server::gateway::web::Web> web_records_delete_;
        std::unique_ptr<engine::server::gateway::web::Web> web_records_update_;
        std::unique_ptr<engine::server::gateway::web::Web> web_families_;
        std::unique_ptr<engine::server::gateway::web::Web> web_tags_;
        std::unique_ptr<engine::server::gateway::web::Web> web_create_family_;
        std::unique_ptr<engine::server::gateway::web::Web> web_update_family_;
        std::unique_ptr<engine::server::gateway::web::Web> web_create_tag_;
        std::unique_ptr<engine::server::gateway::web::Web> web_update_tag_;
    };
} // namespace engine::bridge::endpoints::analysis