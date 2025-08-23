#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <mutex>

namespace engine::server::gateway::web::extend
{
    class Web : public interface::IPlugins<Web>
    {
      public:
        void _plugins() override;

      private:
        void bind_web();
    };
} // namespace engine::server::gateway::web::extend