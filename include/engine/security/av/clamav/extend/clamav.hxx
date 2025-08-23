#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::security::av::clamav::extend
{
    class Clamav : public interface::IPlugins<Clamav>
    {
      public:
        void _plugins();

      private:
        void bind_clamav();
        void bind_options();
    };
} // namespace engine::security::av::clamav::extend