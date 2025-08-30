#include <engine/filesystem/entitys.hxx>
#include <engine/filesystem/extend/filesystem.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::filesystem::extend
{
    void Filesystem::bind_filesystem()
    {
        plugins::Plugins::lua.state.new_usertype<filesystem::Filesystem>(
            "Filesystem",
            "new",
            sol::constructors<filesystem::Filesystem()>(),
            "enqueue_write",
            [](filesystem::Filesystem &self, record::EnqueueTask &task) {
                self.enqueue_write(task);
            },
            "write",
            [](filesystem::Filesystem &self,
               record::File &file,
               const bool relative) { self.write(file, relative); },
            "is_exists",
            [](filesystem::Filesystem &self,
               record::File &file,
               const bool relative) { return self.is_exists(file, relative); },
            "read",
            [](filesystem::Filesystem &self,
               record::File &file,
               const bool relative) { self.read(file, relative); },
            "create_directories",
            [](filesystem::Filesystem &self,
               const std::string &path,
               const bool relative) {
                self.create_directories(path, relative);
            },
            "path",
            sol::property([](filesystem::Filesystem &self) -> std::string & {
                return self.path;
            }),
            "readonly",
            sol::property([](filesystem::Filesystem &self) -> const bool & {
                return self.readonly;
            }),
            "is_running",
            sol::property([](filesystem::Filesystem &self) {
                return self.is_running.load();
            }));
    }

    void Filesystem::bind_enqueuetask()
    {
        plugins::Plugins::lua.state
            .new_usertype<filesystem::record::EnqueueTask>(
                "FileSystemEnqueueTask",
                "id",
                &filesystem::record::EnqueueTask::id,
                "file",
                &filesystem::record::EnqueueTask::file,
                "relative",
                &filesystem::record::EnqueueTask::relative);
    }

    void Filesystem::bind_file()
    {
        plugins::Plugins::lua.state.new_usertype<filesystem::record::File>(
            "File",
            "filename",
            &filesystem::record::File::filename,
            "content",
            &filesystem::record::File::content);
    }

    void Filesystem::_plugins()
    {
        Filesystem::bind_filesystem();
        Filesystem::bind_file();
        Filesystem::bind_enqueuetask();
    }
} // namespace engine::filesystem::extend