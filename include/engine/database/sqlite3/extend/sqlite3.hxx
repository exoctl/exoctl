// #ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::database::sqlite3::extend
{
    class Sqlite3 : public interface::ISubPlugins<Sqlite3>
    {
      public:
        Sqlite3() = default;
        ~Sqlite3() = default;

      private:
        void bind_sqlite3();
    };
} // namespace engine::database::sqlite3

// #endif