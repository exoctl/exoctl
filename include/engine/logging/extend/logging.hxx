#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/lua/lua.hxx>

namespace engine::logging::extend
{
    class Logging : public interface::IPlugins<Logging>
    {
      public:

        void _plugins() override;

      private:
        void bind_logging(engine::lua::StateView &);
    };
} // namespace engine::logging::extend
