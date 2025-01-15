#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/plugins/exception.hxx>

namespace engine
{
    namespace plugins
    {
        class Plugins
        {
          public:
            Plugins(configuration::Configuration &);
            ~Plugins();

            void load_plugin_buff(const std::string &);
            void load_plugin_file(const std::string &);
            void load_plugins_folder(const std::string &);

          private:
        };
    } // namespace plugins
} // namespace engine