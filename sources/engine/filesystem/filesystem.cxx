#include <engine/filesystem/filesystem.hxx>
#include <fmt/core.h>
#include <fstream>

namespace fs = std::filesystem;

namespace engine::filesystem
{
    std::mutex Filesystem::fs_queue_mutex_;
    std::queue<record::EnqueueTask> Filesystem::fs_queue_;
    std::condition_variable Filesystem::fs_queue_cv_;
    std::atomic<bool> Filesystem::is_running = true;
    std::atomic<int> Filesystem::id_counter_ = 0;
    std::string Filesystem::path;
    bool Filesystem::readonly;

    const bool Filesystem::canonical_base(const std::string &base_str,
                                          fs::path &out_base)
    {
        std::error_code ec;
        out_base = fs::weakly_canonical(fs::path(base_str), ec);
        return !(ec || out_base.empty());
    }

    const bool Filesystem::is_within_base(const fs::path &base,
                                          const fs::path &requested)
    {
        std::error_code ec;
        auto b = fs::weakly_canonical(base, ec);
        if (ec)
            return false;
        auto r = fs::weakly_canonical(requested, ec);
        if (ec)
            return false;

        auto itb = b.begin(), endb = b.end();
        auto itr = r.begin(), endr = r.end();
        for (; itb != endb && itr != endr; ++itb, ++itr) {
            if (*itb != *itr)
                return false;
        }
        return itb == endb;
    }

    const bool Filesystem::resolve_secure_path(const fs::path &base,
                                               const std::string &filename,
                                               bool relative,
                                               fs::path &out)
    {
        if (filename.empty())
            return false;

        std::error_code ec;
        fs::path candidate;
        if (relative) {
            candidate = base / fs::path(filename);
        } else {
            fs::path tmp(filename);
            candidate = tmp.is_absolute() ? tmp : (base / tmp);
        }

        out = fs::weakly_canonical(candidate, ec);
        if (ec)
            return false;

        if (!Filesystem::is_within_base(base, out))
            return false;
        return true;
    }

    const bool Filesystem::safe_create_parents(const fs::path &base,
                                               const fs::path &full)
    {
        std::error_code ec;
        auto parent = full.parent_path();
        if (parent.empty())
            return true;
        if (!Filesystem::is_within_base(base, parent))
            return false;
        fs::create_directories(parent, ec);
        return !ec;
    }

    Filesystem::~Filesystem()
    {
        is_running = false;
        fs_queue_cv_.notify_all();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    void Filesystem::setup(const configuration::Configuration &cfg,
                           const logging::Logging &log)
    {
        config_ = cfg;
        log_ = log;
        path = config_.get("filesystem.path").value<std::string>().value();
        readonly = config_.get("filesystem.readonly").value<bool>().value();

        fs::path base;
        if (!canonical_base(path, base)) {
            throw std::runtime_error("Invalid filesystem base path");
        }
        Filesystem::safe_create_parents(base, base);
    }

    void Filesystem::load()
    {
        worker_thread_ = std::thread(&Filesystem::worker, this);
    }

    void Filesystem::enqueue_write(record::EnqueueTask &task)
    {
        std::lock_guard<std::mutex> lock(fs_queue_mutex_);
        task.id = ++id_counter_;
        task.action = type::EnqueueTaskAction::WRITE;
        fs_queue_.push(task);
        fs_queue_cv_.notify_one();
    }

    void Filesystem::enqueue_remove(record::EnqueueTask &task)
    {
        std::lock_guard<std::mutex> lock(fs_queue_mutex_);
        task.id = ++id_counter_;
        task.action = type::EnqueueTaskAction::REMOVE;
        fs_queue_.push(task);
        fs_queue_cv_.notify_one();
    }

    void Filesystem::worker()
    {
        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return;

        while (is_running) {
            std::unique_lock<std::mutex> lock(fs_queue_mutex_);
            fs_queue_cv_.wait(
                lock, [] { return !fs_queue_.empty() || !is_running.load(); });

            if (!is_running)
                break;
            auto task = fs_queue_.front();
            fs_queue_.pop();
            lock.unlock();

            switch (task.action) {
                case type::EnqueueTaskAction::WRITE:
                    Filesystem::write(task.file);
                    break;
                case type::EnqueueTaskAction::REMOVE:
                    Filesystem::remove(task.file);
                    break;
            }
        }
    }

    const bool Filesystem::is_exists(const record::File &file,
                                     const bool relative)
    {
        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return false;

        fs::path full;
        if (!Filesystem::resolve_secure_path(
                base, file.filename, relative, full))
            return false;

        return fs::exists(full);
    }

    void Filesystem::write(const record::File &file, const bool relative)
    {
        if (readonly)
            return;

        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return;

        fs::path full;
        if (!Filesystem::resolve_secure_path(
                base, file.filename, relative, full))
            return;
        if (!Filesystem::safe_create_parents(base, full))
            return;

        std::ofstream ofs(full, std::ios::binary);
        ofs.write(reinterpret_cast<const char *>(file.content.data()),
                  static_cast<std::streamsize>(file.content.size()));
    }

    void Filesystem::read(record::File &file, const bool relative)
    {
        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return;

        fs::path full;
        if (!Filesystem::resolve_secure_path(
                base, file.filename, relative, full))
            return;
        if (!fs::exists(full))
            return;

        std::ifstream ifs(full, std::ios::binary | std::ios::ate);
        auto size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);

        file.content.resize(static_cast<size_t>(size));
        ifs.read(reinterpret_cast<char *>(file.content.data()), size);
    }

    void Filesystem::remove(const record::File &file, const bool relative)
    {
        if (readonly)
            return;

        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return;

        fs::path full;
        if (!Filesystem::resolve_secure_path(
                base, file.filename, relative, full))
            return;

        std::error_code ec;
        fs::remove(full, ec);
    }

    void Filesystem::create_directories(const std::string &dir,
                                        const bool relative)
    {
        fs::path base;
        if (!Filesystem::canonical_base(path, base))
            return;

        fs::path full;
        if (!Filesystem::resolve_secure_path(base, dir, relative, full))
            return;

        std::error_code ec;
        fs::create_directories(full, ec);
    }
} // namespace engine::filesystem
