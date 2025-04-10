#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::configuration::extend
{
    class Configuration : public interface::IBind
#ifdef ENGINE_PRO
        ,
                          public interface::ISubPlugins<Configuration>
#endif
    {
      public:
        void bind_to_lua(engine::lua::StateView &) override;

#ifdef ENGINE_PRO
        void _plugins() override;
#endif

      private:
        void bind_configuration(engine::lua::StateView &);
    };
} // namespace engine::configuration::extend