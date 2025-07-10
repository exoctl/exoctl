#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/lua/lua.hxx>

namespace engine::configuration::extend
{
    class Configuration : 
                          public interface::IPlugins<Configuration>
    {
      public:
        void _plugins() override;

      private:
        void bind_configuration(engine::lua::StateView &);
    };
} // namespace engine::configuration::extend