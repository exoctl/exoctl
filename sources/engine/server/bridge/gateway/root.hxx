#pragma once

#include <engine/interfaces/igateway.hxx>
#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_ROOT "/"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            class Root : public interface::IGateway
            {
              public:
                Root(Server &);
                ~Root();

                void load() const override;

              private:
                Server &m_server;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::Web<>> m_web_root;

                void prepare();
                void root();
                void plugins();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine