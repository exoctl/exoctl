#pragma once

#include <LIEF/LIEF.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <engine/bridge/map/map.hxx>
#include <engine/focades/analysis/analysis.hxx>
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
        focades::analysis::Analysis analysis;

      private:
        server::Server *server_;
        mutable map::Map map_;
        bool enable_;

        std::unique_ptr<engine::server::gateway::web::Web> web_scan_;
        std::unique_ptr<engine::server::gateway::web::Web> web_scan_threats_;
        std::unique_ptr<engine::server::gateway::web::Web> web_records_;
        std::unique_ptr<engine::server::gateway::web::Web> web_update_;


        void scan();
        void update();
        void rescan();
        void records();
        void scan_threats();
    };
} // namespace engine::bridge::endpoints::analysis
