#pragma once

#include <engine/interfaces/iluaopenlibrary.hxx>
#include <engine/interfaces/iplugins.hxx>

namespace engine::database::extend
{
    class Database : public interface::ILuaOpenLibrary,
                     public interface::IPlugins<Database>
    {
      public:
        Database() = default;
        ~Database() = default;
        void lua_open_library(engine::lua::StateView &) override;
        void _plugins() override;

      private:
        void bind_database(engine::lua::StateView &);
    };
} // namespace engine::database::extend