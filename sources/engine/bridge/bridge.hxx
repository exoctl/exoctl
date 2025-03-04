#pragma once

// clang-format off
#include <engine/bridge/endpoints/parser.hxx>
// clang-format on
#include <engine/bridge/endpoints/analysis.hxx>
#include <engine/bridge/endpoints/data.hxx>
#include <engine/bridge/entitys.hxx>

#ifdef ENGINE_PRO
#include <engine/bridge/endpoints/plugins.hxx>
#endif

#include <engine/bridge/extend/bridge.hxx>

#include <engine/bridge/endpoints/reverse.hxx>
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
            Bridge();
            ~Bridge() = default;

            friend class extend::Bridge;

            void load();
            void setup(server::Server &);

#ifdef ENGINE_PRO
            static std::shared_ptr<bridge::endpoints::Plugins> plugins;
#endif
            static std::shared_ptr<bridge::endpoints::Parser> parser;
            static std::shared_ptr<bridge::endpoints::Reverse> reverse;
            static std::shared_ptr<bridge::endpoints::Data> data;
            static std::shared_ptr<bridge::endpoints::Analysis> analysis;

          private:
            server::Server *m_server;
            std::vector<bridge::record::Bridge> m_endpoints;
        };
    } // namespace bridge
} // namespace engine
