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

    Filesystem::Filesystem() : m_readonly(false)
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

    void Filesystem::setup(const configuration::Configuration &p_config,
                           const logging::Logging &p_log)
    {
        m_config = p_config;
        m_log = p_log;

        m_base_path =
            m_config.get("filesystem.path").value<std::string>().value();
        m_readonly = m_config.get("filesystem.readonly").value<bool>().value();

        std::filesystem::create_directories(m_base_path);
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
                record::EnqueueTask &task = m_fs_queue.front();
                m_fs_queue.pop();
                lock.unlock();

                if (m_readonly) {
                    m_log.error(
                        fmt::format("Cannot write file '{}': Filesystem is "
                                    "readonly (Task ID {})",
                                    task.filename,
                                    task.id));
                } else {
                    m_log.info(
                        fmt::format("Processing write task ID {} for file '{}'",
                                    task.id,
                                    task.filename));
                    write(task.filename, task.content);
                }

                lock.lock();
            }
        }
    }

    void Filesystem::write(const std::string &filename,
                           const std::string &content)
    {
        if (!m_readonly) {
            m_log.error(fmt::format("Cannot write file '{}': Filesystem is "
                                    "readonly",
                                    filename));
            return;
        }

        std::string full_path = m_base_path + "/" + filename;
        std::ofstream ofs(full_path, std::ios::binary);
        if (!ofs) {
            m_log.error(
                fmt::format("Failed to open file for writing: {}", full_path));
            return;
        }
        ofs << content;
        m_log.info(fmt::format("Wrote file: {}", full_path));
    }

    const std::string Filesystem::read(const std::string &filename)
    {
        std::string full_path = m_base_path + "/" + filename;
        std::ifstream ifs(full_path, std::ios::binary);
        if (!ifs) {
            m_log.error(
                fmt::format("Failed to open file for reading: {}", full_path));
            return {};
        }
        std::string content((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
        return content;
    }
} // namespace engine::filesystem
