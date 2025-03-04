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
        void _plugins() override;
        void bind_to_lua(sol::state_view &) override;

      private:
        void bind_bridge(sol::state_view &);
    };
} // namespace engine::bridge::extend
