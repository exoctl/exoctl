#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::bridge::extend
{
    class Bridge : public interface::IBind
        ,
                   public interface::ISubPlugins<Bridge>
    {
      public:
        void _plugins() override;
        void bind_to_lua(engine::lua::StateView &) override;

      private:
        void bind_bridge(engine::lua::StateView &);
    };
} // namespace engine::bridge::extend
