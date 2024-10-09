#pragma once

#include <engine/crowapp/bridge/entitys.hxx>
#include <engine/crowapp/bridge/gateway/analysis.hxx>
#include <engine/crowapp/bridge/gateway/data.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace crowapp
{
    class Bridge
    {
      public:
        Bridge(CrowApp &);
        ~Bridge();

        void load();
        const std::vector<bridge::record::Bridge> &get_endpoints();

      private:
        CrowApp &m_crowapp;
        std::vector<bridge::record::Bridge> m_endpoints;

        std::unique_ptr<bridge::Analysis> m_analysis;
        std::unique_ptr<bridge::Data> m_data;
    };
} // namespace crowapp
