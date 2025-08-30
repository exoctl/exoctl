#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::security::yara::extend
{
    class Yara : public interface::IPlugins<Yara>
    {
      public:
        Yara() = default;
        ~Yara() = default;

        void _plugins() override;

      private:
        inline void bind_flags();
        inline void bind_import();
        inline void bind_string();
        inline void bind_namespace();
        inline void bind_meta();
        inline void bind_rule();
        inline void bind_stream();
        inline void bind_yara();
    };
} // namespace engine::security::yara::extend
