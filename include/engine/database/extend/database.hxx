#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::database::extend
{
    class Database : public interface::IPlugins<Database>
    {
      public:
        Database() = default;
        ~Database() = default;

      private:
        void bind_database();
    };
} // namespace engine::database::sqlite3::extend