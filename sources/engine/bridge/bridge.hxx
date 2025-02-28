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

#include <engine/bridge/endpoints/reverse.hxx>
#include <engine/server/server.hxx>
#include <memory>
#include <vector>

namespace engine
{
    namespace bridge
    {
        class Bridge : public interface::IBind
#ifdef ENGINE_PRO
            ,
                       public interface::IPlugins
#endif
        {
          public:
            Bridge() = default;
            ~Bridge() = default;

            void load();
            void setup(server::Server &);
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
            void bind_to_lua(sol::state_view &) override;

          private:
            server::Server *m_server;
            std::vector<bridge::record::Bridge> m_endpoints;

            std::unique_ptr<bridge::endpoints::Analysis> m_analysis;
#ifdef ENGINE_PRO
            std::unique_ptr<bridge::endpoints::Plugins> m_plugins;
#endif
            std::unique_ptr<bridge::endpoints::Parser> m_parser;
            std::unique_ptr<bridge::endpoints::Reverse> m_reverse;
            std::unique_ptr<bridge::endpoints::Data> m_data;
        };
    } // namespace bridge
} // namespace engine
