#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::logging::extend
{
    class Logging : public interface::IBind
        ,
                    public interface::ISubPlugins<Logging>
    {
      public:
        void bind_to_lua(engine::lua::StateView &) override;

        void _plugins() override;

      private:
        void bind_logging(engine::lua::StateView &);
    };
} // namespace engine::logging::extend
