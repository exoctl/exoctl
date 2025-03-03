#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::server::gateway::web::plugin
{
    class Web : public interface::ISubPlugins<Web>
    {
      public:
        void _plugins() override;

      private:
    };
} // namespace engine::server::gateway::web::plugin

#endif