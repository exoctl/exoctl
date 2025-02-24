#pragma once

// clang-format off
#include <engine/server/bridge/endpoints/parser.hxx>
// clang-format on
#include <engine/server/bridge/endpoints/analysis.hxx>
#include <engine/server/bridge/endpoints/data.hxx>
#include <engine/server/bridge/entitys.hxx>

#ifdef ENGINE_PRO
#include <engine/server/bridge/endpoints/plugins.hxx>
#endif

#include <engine/server/bridge/endpoints/reverse.hxx>
#include <engine/server/server.hxx>
#include <memory>
#include <vector>

namespace engine
{
    namespace server
    {
        class Bridge
#ifdef ENGINE_PRO
            : public interface::IPlugins
#endif
        {
          public:
            Bridge() = default;
            ~Bridge() = default;

            void load();
            void setup(Server &);
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
          private:
            Server *m_server;
            std::vector<bridge::record::Bridge> m_endpoints;

            std::unique_ptr<bridge::endpoints::Analysis> m_analysis;
#ifdef ENGINE_PRO
            std::unique_ptr<bridge::endpoints::Plugins> m_plugins;
#endif
            std::unique_ptr<bridge::endpoints::Parser> m_parser;
            std::unique_ptr<bridge::endpoints::Reverse> m_reverse;
            std::unique_ptr<bridge::endpoints::Data> m_data;
        };
    } // namespace server
} // namespace engine
