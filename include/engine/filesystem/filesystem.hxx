#pragma once

#include <atomic>
#include <condition_variable>
#include <engine/configuration/configuration.hxx>
#include <engine/filesystem/entitys.hxx>
#include <engine/filesystem/extend/filesystem.hxx>
#include <engine/logging/logging.hxx>
#include <filesystem>
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
        static void enqueue_remove(record::EnqueueTask &);

        static void remove(const record::File &, const bool = true);
        static void write(const record::File &, const bool = true);
        [[nodiscard]] static const  bool is_exists(const record::File &,
                                            const bool = true);
        static void read(record::File &, const bool = true);
        static void create_directories(const std::string &, const bool = true);

        static std::string path;
        static bool readonly;
        static std::atomic<bool> is_running;

      private:
        configuration::Configuration config_;
        logging::Logging log_;

        static std::mutex fs_queue_mutex_;
        static std::queue<record::EnqueueTask> fs_queue_;
        static std::condition_variable fs_queue_cv_;
        static std::atomic<int> id_counter_;

        std::thread worker_thread_;
        void worker();

        static inline const bool canonical_base(const std::string &,
                                   std::filesystem::path &);
        static inline const  bool is_within_base(const std::filesystem::path &,
                                   const std::filesystem::path &);
        static inline const  bool resolve_secure_path(const std::filesystem::path &,
                                        const std::string &,
                                        bool,
                                        std::filesystem::path &);
        static inline const  bool safe_create_parents(const std::filesystem::path &,
                                        const std::filesystem::path &);
    };
} // namespace engine::filesystem
