#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::configuration::plugin
{
    class Configuration : public interface::IBind
#ifdef ENGINE_PRO
        ,
                          public interface::ISubPlugins<Configuration>
#endif
    {
      public:
        void bind_to_lua(sol::state_view &) override;
#ifdef ENGINE_PRO
        void _plugins() override;
#endif
      private:
        void bind_configuration(sol::state_view &);
    };
} // namespace engine::configuration::plugin