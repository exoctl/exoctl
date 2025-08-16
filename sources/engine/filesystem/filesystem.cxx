#include <engine/filesystem/filesystem.hxx>
#include <filesystem>
#include <fmt/core.h>
#include <fstream>

namespace engine::filesystem
{
    std::mutex Filesystem::m_fs_queue_mutex;
    std::queue<record::EnqueueTask> Filesystem::m_fs_queue;
    std::condition_variable Filesystem::m_fs_queue_cv;
    std::atomic<bool> Filesystem::is_running = true;
    std::atomic<int> Filesystem::m_id_counter = 0;
    std::string Filesystem::path;
    bool Filesystem::readonly;

    Filesystem::Filesystem()
    {
    }

    Filesystem::~Filesystem()
    {
        m_fs_queue_cv.notify_all();
        is_running = false;

        if (m_worker_thread.joinable()) {
            m_worker_thread.join();
        }
    }

    const bool Filesystem::is_exists(const record::File &p_file)
    {
        std::error_code ec;
        return std::filesystem::exists(
            std::filesystem::path(path) / p_file.filename, ec);
    }

    void Filesystem::setup(const configuration::Configuration &p_config,
                           const logging::Logging &p_log)
    {
        m_config = p_config;
        m_log = p_log;

        path = m_config.get("filesystem.path").value<std::string>().value();
        readonly = m_config.get("filesystem.readonly").value<bool>().value();

        std::filesystem::create_directories(path);
    }

    void Filesystem::load()
    {
        m_worker_thread = std::thread(&Filesystem::worker, this);
    }

    void Filesystem::enqueue_write(record::EnqueueTask &p_task)
    {
        if (!is_running)
            return;

        p_task.id = ++m_id_counter;

        std::lock_guard<std::mutex> lock(m_fs_queue_mutex);
        m_fs_queue.push(p_task);
        m_fs_queue_cv.notify_one();
    }

    void Filesystem::worker()
    {
        m_log.info("Filesystem Worker thread started running.");
        while (is_running) {
            std::unique_lock<std::mutex> lock(m_fs_queue_mutex);
            m_fs_queue_cv.wait(
                lock, [] { return !m_fs_queue.empty() || !is_running; });

            while (!m_fs_queue.empty()) {
                record::EnqueueTask task = m_fs_queue.front();
                m_fs_queue.pop();
                lock.unlock();

                Filesystem::write(task.file);

                lock.lock();
            }
        }
    }

    void Filesystem::write(const record::File &p_file)
    {
        if (readonly) {
            return;
        }

        std::filesystem::path full_path =
            std::filesystem::path(path) / p_file.filename;

        std::ofstream ofs(full_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return;
        }

        ofs.write(p_file.content.data(),
                  static_cast<std::streamsize>(p_file.content.size()));
    }

    const std::string Filesystem::read(const record::File &p_file)
    {
        std::filesystem::path full_path =
            std::filesystem::path(path) / p_file.filename;

        std::ifstream ifs(full_path, std::ios::binary);
        if (!ifs) {
            return {};
        }

        ifs.seekg(0, std::ios::end);
        std::string content;
        content.resize(static_cast<size_t>(ifs.tellg()));
        ifs.seekg(0, std::ios::beg);

        ifs.read(content.data(), static_cast<std::streamsize>(content.size()));
        return content;
    }
} // namespace engine::filesystem
