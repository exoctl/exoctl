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

        void setup(const configuration::Configuration &,
                   const logging::Logging &);
        void load();

        static void enqueue_write(record::EnqueueTask &);
        static void write(const record::File &);
        static const bool is_exists(const record::File &);
        static const std::string read(const record::File &);
        static std::string path;
        static bool readonly;
        static std::atomic<bool> is_running;

      private:
        configuration::Configuration m_config;
        logging::Logging m_log;

        static std::mutex m_fs_queue_mutex;
        static std::queue<record::EnqueueTask> m_fs_queue;
        static std::condition_variable m_fs_queue_cv;
        static std::atomic<int> m_id_counter;

        std::thread m_worker_thread;
        void worker();
    };
} // namespace engine::filesystem
