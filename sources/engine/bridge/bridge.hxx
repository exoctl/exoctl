#pragma once

// clang-format off
#include <LIEF/LIEF.hpp>
// clang-format on
#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/entitys.hxx>
#include <engine/bridge/endpoints/plugins/plugins.hxx>
#include <engine/bridge/extend/bridge.hxx>
#include <engine/database/database.hxx>
#include <engine/server/server.hxx>
#include <memory>
#include <vector>

namespace engine
{
    namespace bridge
    {
        class Bridge;

        class Bridge
        {
          public:
            Bridge() = default;
            ~Bridge() = default;
            friend class extend::Bridge;
            void load();
            void setup(server::Server &, database::Database &);

            static std::shared_ptr<bridge::endpoints::Plugins> plugins;
            static std::shared_ptr<bridge::endpoints::Analysis> analysis;

          private:
            server::Server *m_server;
            database::Database *m_database;
            std::vector<bridge::record::Bridge> m_endpoints;
        };
    } // namespace bridge
} // namespace engine
