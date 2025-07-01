#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::configuration::extend
{
    class Configuration : public interface::ILuaOpenLibrary,
                          public interface::IPlugins<Configuration>
    {
      public:
        void lua_open_library(engine::lua::StateView &) override;

        void _plugins() override;

      private:
        void bind_configuration(engine::lua::StateView &);
    };
} // namespace engine::configuration::extend