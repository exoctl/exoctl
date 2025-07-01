#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::server::gateway::web::extend
{
    class Web : public interface::IPlugins<Web>
    {
      public:
        void _plugins() override;

      private:
    };
} // namespace engine::server::gateway::web::extend