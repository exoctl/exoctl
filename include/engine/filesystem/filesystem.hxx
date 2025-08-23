#pragma once

#include <atomic>
#include <condition_variable>
#include <engine/configuration/configuration.hxx>
#include <engine/filesystem/entitys.hxx>
#include <engine/filesystem/extend/filesystem.hxx>
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
        friend class extend::Filesystem;

        Filesystem() = default;
        ~Filesystem();

        void setup(const configuration::Configuration &,
                   const logging::Logging &);
        void load();

        static void enqueue_write(record::EnqueueTask &);
        static void write(const record::File &, const bool = true);
        [[nodiscard]] static const bool is_exists(const record::File &, const bool = true);
        static void read(record::File &, const bool = true);
        static void create_directories(const std::string &, const bool = true);
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
