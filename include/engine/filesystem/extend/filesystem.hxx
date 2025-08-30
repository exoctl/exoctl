#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/lua/lua.hxx>

namespace engine::filesystem::extend
{
    class Filesystem : public interface::IPlugins<Filesystem>
    {
      public:
        Filesystem() = default;
        ~Filesystem() = default;

        void _plugins() override;

      private:
        void bind_filesystem();
        void bind_enqueuetask();
        void bind_file();
    };
} // namespace engine::filesystem::extend