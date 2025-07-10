#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::bridge::extend
{
    class Bridge :

        public interface::IPlugins<Bridge>
    {
      public:
        void _plugins() override;

      private:
        void bind_bridge(engine::lua::StateView &);
    };
} // namespace engine::bridge::extend
