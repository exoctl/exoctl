#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::database::extend
{
    class Database : public interface::IPlugins<Database>
    {
      public:
        Database() = default;
        ~Database() = default;
        void _plugins() override;

      private:
        void bind_database(engine::lua::StateView &);
    };
} // namespace engine::database::extend