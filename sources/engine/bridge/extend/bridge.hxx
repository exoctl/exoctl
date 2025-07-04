#pragma once

#include <engine/interfaces/iluaopenlibrary.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::bridge::extend
{
    class Bridge : public interface::ILuaOpenLibrary
        ,
                   public interface::IPlugins<Bridge>
    {
      public:
        void _plugins() override;
        void lua_open_library(engine::lua::StateView &) override;

      private:
        void bind_bridge(engine::lua::StateView &);
    };
} // namespace engine::bridge::extend
