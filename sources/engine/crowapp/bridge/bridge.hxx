#pragma once

// clang-format off
#include <engine/crowapp/bridge/gateway/parser.hxx>
// clang-format on
#include <engine/crowapp/bridge/entitys.hxx>
#include <engine/crowapp/bridge/gateway/analysis.hxx>
#include <engine/crowapp/bridge/gateway/data.hxx>
#include <engine/crowapp/bridge/gateway/rev.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <memory>
#include <vector>

namespace engine
{
    namespace crowapp
    {
        class Bridge
        {
          public:
            Bridge(CrowApp &);
            ~Bridge();

            void load();

          private:
            CrowApp &m_crowapp;
            std::vector<bridge::record::Bridge> m_endpoints;

            std::unique_ptr<bridge::Analysis> m_analysis;
            std::unique_ptr<bridge::Parser> m_parser;
            std::unique_ptr<bridge::Rev> m_rev;
            std::unique_ptr<bridge::Data> m_data;
        };
    } // namespace crowapp
} // namespace engine
