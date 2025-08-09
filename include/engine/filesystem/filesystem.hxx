#pragma once

#include <atomic>
#include <condition_variable>
#include <engine/configuration/configuration.hxx>
#include <engine/filesystem/entitys.hxx>
#include <engine/logging/logging.hxx>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace engine::filesystem
{
    class Filesystem
    {
      public:
        Filesystem();
        ~Filesystem();

        void setup(const configuration::Configuration &p_config,
                   const logging::Logging &p_log);
        void load();

        static void enqueue_write(record::EnqueueTask &);
        void write(const std::string &filename, const std::string &content);
        const std::string read(const std::string &filename);

      private:
        configuration::Configuration m_config;
        logging::Logging m_log;

        std::string m_base_path;
        bool m_readonly;

        static std::mutex m_fs_queue_mutex;
        static std::queue<record::EnqueueTask> m_fs_queue;
        static std::condition_variable m_fs_queue_cv;
        static std::atomic<bool> is_running;
        static std::atomic<int> m_id_counter;

        std::thread m_worker_thread;
        void worker();
    };
} // namespace engine::filesystem
