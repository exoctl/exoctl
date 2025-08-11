#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <stdint.h>

namespace engine::focades::analysis
{
    Analysis::Analysis()
        : metadata(std::make_shared<focades::analysis::metadata::Metadata>()),
          scan_av_clamav(
              std::make_shared<focades::analysis::scan::av::clamav::Clamav>()),
          scan_yara(std::make_shared<focades::analysis::scan::yara::Yara>()),
          is_running(true), max_queue_size(0), scan_queue_size(0),
          m_id_counter(0)
    {
    }

    Analysis::~Analysis()
    {
        m_scan_cv.notify_all();
        is_running = false;

        if (m_scan_worker.joinable())
            m_scan_worker.join();
    }

    void Analysis::_plugins()
    {
        plugins::Plugins::lua.state.new_usertype<focades::analysis::Analysis>(
            "Analysis",
            "scan",
            sol::property(
                [](focades::analysis::Analysis &self)
                    -> focades::analysis::Analysis & { return self; }),
            sol::meta_function::index,
            [](focades::analysis::Analysis &self,
               const std::string &key,
               sol::this_state ts) {
                sol::state_view lua(ts);
                if (key == "clamav" && self.scan_av_clamav)
                    return sol::make_object(lua, std::ref(self.scan_av_clamav->clamav));
                if (key == "yara" && self.scan_yara)
                    return sol::make_object(lua,  std::ref(self.scan_yara->yara));
                return sol::make_object(lua, sol::nil);
            },
            "enqueue_scan",
            &focades::analysis::Analysis::enqueue_scan,
            "is_running",
            sol::property(
                [](const focades::analysis::Analysis &p_self) -> const bool {
                    return p_self.is_running.load();
                }),
            "scan_queue_size",
            sol::property(
                [](const focades::analysis::Analysis &p_self) -> const size_t {
                    return p_self.scan_queue_size.load();
                }),
            "max_queue_size",
            &focades::analysis::Analysis::max_queue_size);
    }

    void Analysis::setup(configuration::Configuration &p_config,
                         logging::Logging &p_log)
    {
        m_config = &p_config;
        m_log = &p_log;

        max_queue_size = p_config.get("focades.analysis.max_queue_size")
                             .value<size_t>()
                             .value();

        scan_yara->setup(p_config);
        scan_av_clamav->setup(p_config);

        m_scan_worker = std::thread(&Analysis::worker, this);
    }

    void Analysis::load() const
    {
        TRY_BEGIN()
        m_log->info("Loading rules yara ...");
        scan_yara->load();

        m_log->info("Loading rules clamav ...");
        scan_av_clamav->load([&](unsigned int p_total_rules) {
            m_log->info(
                "Successfully loaded rules. Total Clamav rules count: {:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            m_log->error("{}", e.what());
            throw exception::Load(e.what());
        })
    }

    void Analysis::enqueue_scan(record::EnqueueTask &p_task)
    {
        std::lock_guard<std::mutex> lock(m_scan_mutex);
        if (m_scan_queue.size() >= max_queue_size || !is_running) {
            throw exception::EnqueueScan(
                fmt::format("Scan queue({}) is full({}) or not is running({}) ",
                            m_scan_queue.size(),
                            max_queue_size,
                            is_running.load()));
        }

        p_task.id = ++m_id_counter;

        m_scan_queue.push(p_task);
        m_scan_cv.notify_one();
    }

    void Analysis::worker()
    {
        m_log->info("Analysis Worker thread started running.");

        while (is_running) {
            std::unique_lock<std::mutex> lock(m_scan_mutex);
            m_scan_cv.wait(
                lock, [this] { return !m_scan_queue.empty() || !is_running; });

            if (!is_running && m_scan_queue.empty()) {
                break;
            }

            while (!m_scan_queue.empty()) {
                record::EnqueueTask &task = m_scan_queue.front();
                m_scan_queue.pop();
                scan_queue_size = m_scan_queue.size();
                lock.unlock();

                parser::Json json;

                m_log->info(
                    fmt::format("Processing scan from task {} queue({}) ",
                                task.id,
                                scan_queue_size.load()));

                TRY_BEGIN()

                metadata->parse(
                    task.buf,
                    [&](focades::analysis::metadata::record::DTO *p_dto) {
                        if (!filesystem::Filesystem::is_exists(p_dto->sha256)) {
                            filesystem::Filesystem::write(p_dto->sha256,
                                                          task.buf);
                        }
                    });

                scan_av_clamav->scan(
                    task.buf,
                    [&](focades::analysis::scan::av::clamav::record::DTO
                            *p_dto) {
                        // work here
                    });

                scan_yara->scan(
                    task.buf,
                    [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                        // work here
                    });
                TRY_END()
                CATCH(security::av::clamav::exception::Scan,
                      { m_log->error("Erro ClamAV: {}", e.what()); })
                CATCH(security::yara::exception::Scan,
                      { m_log->error("Erro YARA: {}", e.what()); })

                lock.lock();
            }
        }
    }
} // namespace engine::focades::analysis
