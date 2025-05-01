#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::configuration::extend
{
    class Configuration : public interface::IBind,
                          public interface::ISubPlugins<Configuration>
    {
      public:
        void bind_to_lua(engine::lua::StateView &) override;

        void _plugins() override;

      private:
        void bind_configuration(engine::lua::StateView &);
    };
} // namespace engine::configuration::extend