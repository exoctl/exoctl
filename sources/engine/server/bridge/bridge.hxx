#pragma once

// clang-format off
#include <engine/server/bridge/gateway/parser.hxx>
// clang-format on
#include <engine/server/bridge/entitys.hxx>
#include <engine/server/bridge/gateway/analysis.hxx>
#include <engine/server/bridge/gateway/data.hxx>
#include <engine/server/bridge/gateway/rev.hxx>
#include <engine/server/bridge/gateway/root.hxx>
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
            Bridge(Server &);
            ~Bridge() = default;

            void load();
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
          private:
            Server &m_server;
            std::vector<bridge::record::Bridge> m_endpoints;

            std::unique_ptr<bridge::Analysis> m_analysis;
            std::unique_ptr<bridge::Root> m_root;
            std::unique_ptr<bridge::Parser> m_parser;
            std::unique_ptr<bridge::Rev> m_rev;
            std::unique_ptr<bridge::Data> m_data;
        };
    } // namespace server
} // namespace engine
