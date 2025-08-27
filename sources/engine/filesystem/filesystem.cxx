#include <engine/filesystem/filesystem.hxx>
#include <filesystem>
#include <fmt/core.h>
#include <fstream>

namespace engine::filesystem
{
    std::mutex Filesystem::fs_queue_mutex_;
    std::queue<record::EnqueueTask> Filesystem::fs_queue_;
    std::condition_variable Filesystem::fs_queue_cv_;
    std::atomic<bool> Filesystem::is_running = true;
    std::atomic<int> Filesystem::id_counter_ = 0;
    std::string Filesystem::path;
    bool Filesystem::readonly;

    Filesystem::~Filesystem()
    {
        fs_queue_cv_.notify_all();
        is_running = false;

        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    const bool Filesystem::is_exists(const record::File &p_file,
                                     bool p_relative)
    {
        const auto full_path =
            p_relative ? std::filesystem::path(path) / p_file.filename
                       : std::filesystem::path(p_file.filename);

        std::error_code ec;
        return std::filesystem::exists(full_path, ec);
    }

    void Filesystem::setup(const configuration::Configuration &p_config,
                           const logging::Logging &p_log)
    {
        config_ = p_config;
        log_ = p_log;

        path = config_.get("filesystem.path").value<std::string>().value();
        readonly = config_.get("filesystem.readonly").value<bool>().value();

        Filesystem::create_directories(path, false);
    }

    void Filesystem::create_directories(const std::string &p_path,
                                        const bool p_relative)
    {
        const auto full_path = p_relative ? std::filesystem::path(path) / p_path
                                          : std::filesystem::path(p_path);

        std::filesystem::create_directories(full_path);
    }

    void Filesystem::load()
    {
        worker_thread_ = std::thread(&Filesystem::worker, this);
    }

    void Filesystem::enqueue_write(record::EnqueueTask &p_task)
    {
        if (!is_running)
            return;

        p_task.id = ++id_counter_;
        p_task.action = type::EnqueueTaskAction::WRITE;

        {
            std::lock_guard<std::mutex> lock(fs_queue_mutex_);
            fs_queue_.push(p_task);
        }

        fs_queue_cv_.notify_one();
    }

    void Filesystem::enqueue_remove(record::EnqueueTask &p_task)
    {
        if (!is_running)
            return;

        p_task.id = ++id_counter_;
        p_task.action = type::EnqueueTaskAction::REMOVE;

        {
            std::lock_guard<std::mutex> lock(fs_queue_mutex_);
            fs_queue_.push(p_task);
        }

        fs_queue_cv_.notify_one();
    }

    void Filesystem::worker()
    {
        log_.info("Filesystem Worker thread started running.");
        while (is_running) {
            std::unique_lock<std::mutex> lock(fs_queue_mutex_);
            fs_queue_cv_.wait(lock,
                              [] { return !fs_queue_.empty() || !is_running; });

            while (!fs_queue_.empty()) {
                record::EnqueueTask task = fs_queue_.front();
                fs_queue_.pop();
                lock.unlock();

                switch (task.action) {
                    case type::EnqueueTaskAction::REMOVE:
                        Filesystem::remove(task.file, task.relative);
                        break;
                    case type::EnqueueTaskAction::WRITE:
                        Filesystem::write(task.file, task.relative);
                        break;
                }

                lock.lock();
            }
        }
    }

    void Filesystem::write(const record::File &p_file, const bool p_relative)
    {
        if (readonly) {
            return;
        }

        const auto full_path =
            p_relative ? std::filesystem::path(path) / p_file.filename
                       : std::filesystem::path(p_file.filename);

        std::ofstream ofs(full_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return;
        }

        ofs.write(p_file.content.data(),
                  static_cast<std::streamsize>(p_file.content.size()));
    }

    void Filesystem::read(record::File &p_file, const bool p_relative)
    {
        const auto full_path =
            p_relative ? std::filesystem::path(path) / p_file.filename
                       : std::filesystem::path(p_file.filename);

        std::ifstream ifs(full_path, std::ios::binary);
        if (!ifs) {
            return;
        }

        ifs.seekg(0, std::ios::end);
        p_file.content.resize(static_cast<size_t>(ifs.tellg()));
        ifs.seekg(0, std::ios::beg);

        ifs.read(p_file.content.data(),
                 static_cast<std::streamsize>(p_file.content.size()));
    }

    void Filesystem::remove(const record::File &p_file, const bool p_relative)
    {
        if (readonly) {
            return;
        }

        const auto full_path =
            p_relative ? std::filesystem::path(path) / p_file.filename
                       : std::filesystem::path(p_file.filename);

        std::error_code ec;
        std::filesystem::remove(full_path, ec);
    }
} // namespace engine::filesystem
