#pragma once

#include <engine/interfaces/iluaopenlibrary.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::logging::extend
{
    class Logging : public interface::ILuaOpenLibrary
        ,
                    public interface::IPlugins<Logging>
    {
      public:
        void lua_open_library(engine::lua::StateView &) override;

        void _plugins() override;

      private:
        void bind_logging(engine::lua::StateView &);
    };
} // namespace engine::logging::extend
