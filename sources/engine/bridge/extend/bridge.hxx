#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::bridge::extend
{
    class Bridge : public interface::IBind
#ifdef ENGINE_PRO
        ,
                   public interface::ISubPlugins<Bridge>
#endif
    {
      public:
#ifdef ENGINE_PRO
        void _plugins() override;
#endif
        void bind_to_lua(engine::lua::StateView &) override;

      private:
        void bind_bridge(engine::lua::StateView &);
    };
} // namespace engine::bridge::extend
