#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::logging::extend
{
    class Logging : public interface::IBind
#ifdef ENGINE_PRO
        ,
                    public interface::ISubPlugins<Logging>
#endif
    {
      public:
        void bind_to_lua(engine::lua::StateView &) override;

#ifdef ENGINE_PRO
        void _plugins() override;
#endif

      private:
        void bind_logging(engine::lua::StateView &);
    };
} // namespace engine::logging::extend
