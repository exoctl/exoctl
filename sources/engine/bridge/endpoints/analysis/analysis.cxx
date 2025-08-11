#include "entitys.hxx"
#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <stdint.h>

namespace engine::bridge::endpoints::analysis
{
    Analysis::Analysis()
        : m_map(BASE_ANALYSIS),
          m_metadata(std::make_shared<focades::analysis::metadata::Metadata>()),
          m_scan_av_clamav(
              std::make_shared<focades::analysis::scan::av::clamav::Clamav>()),
          m_scan_yara(std::make_shared<focades::analysis::scan::yara::Yara>()),
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
        focades::analysis::scan::yara::Yara::plugins();

        plugins::Plugins::lua.state.new_usertype<endpoints::analysis::Analysis>(
            "Analysis",
            "scan",
            &endpoints::analysis::Analysis::m_scan_yara,
            "enqueue_scan",
            &endpoints::analysis::Analysis::enqueue_scan,
            "is_running",
            sol::property(
                [](const endpoints::analysis::Analysis &p_self) -> const bool {
                    return p_self.is_running.load();
                }),
            "scan_queue_size",
            sol::property(
                [](const endpoints::analysis::Analysis &p_self)
                    -> const size_t { return p_self.scan_queue_size.load(); }),
            "max_queue_size",
            &endpoints::analysis::Analysis::max_queue_size,
            "min_binary_size",
            &endpoints::analysis::Analysis::min_binary_size);
    }

    void Analysis::setup(server::Server &p_server)
    {
        m_server = &p_server;

        if (!p_server.config->get("bridge.endpoint.analysis.enable")
                 .value<bool>()
                 .value()) {
            m_server->log->warn("Gateway analysis not enabled");
            return;
        }

        max_queue_size =
            m_server->config
                ->get("bridge.endpoint.analysis.scan.max_queue_size")
                .value<size_t>()
                .value();

        min_binary_size =
            m_server->config
                ->get("bridge.endpoint.analysis.scan.min_binary_size")
                .value<size_t>()
                .value();

        m_scan_yara->setup(*m_server->config);
        m_scan_av_clamav->setup(*m_server->config);

        m_scan_worker = std::thread(&Analysis::worker, this);

        scan();
        scan_yara();
        scan_av_clamav();
    }

    void Analysis::load() const
    {
        if (m_server->config->get("bridge.endpoint.analysis.enable")
                .value<bool>()
                .value()) {
            TRY_BEGIN()
            m_server->log->info("Loading rules yara ...");
            m_scan_yara->load_rules();

            m_server->log->info("Loading rules clamav ...");
            m_scan_av_clamav->load_rules([&](unsigned int p_total_rules) {
                m_server->log->info(
                    "Successfully loaded rules. Total Clamav rules count: {:d}",
                    p_total_rules);
            });
            TRY_END()
            CATCH(security::yara::exception::LoadRules, {
                m_server->log->error("{}", e.what());
                throw exception::Abort(e.what());
            })

            m_map.get_routes(
                [&](const std::string p_route) { m_map.call_route(p_route); });
        }
    }

    void Analysis::enqueue_scan(record::EnqueueTask &p_task)
    {
        std::lock_guard<std::mutex> lock(m_scan_mutex);
        if (m_scan_queue.size() >= max_queue_size || !is_running) {
            throw exception::ParcialAbort(fmt::format(
                "Scan queue({}) is full or not is_running ", max_queue_size));
        }

        p_task.id = ++m_id_counter;

        m_scan_queue.push(p_task);
        m_scan_cv.notify_one();
    }

    void Analysis::worker()
    {
        m_server->log->info("Analysis Worker thread started running.");

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

                m_server->log->info(
                    fmt::format("Processing scan from task {} queue({}) ",
                                task.id,
                                scan_queue_size.load()));

                TRY_BEGIN()

                m_metadata->parse(
                    task.buf,
                    [&](focades::analysis::metadata::record::DTO *p_dto) {
                        filesystem::Filesystem::write(p_dto->sha256, task.buf);
                    });

                m_scan_av_clamav->scan(
                    task.buf,
                    [&](focades::analysis::scan::av::clamav::record::DTO
                            *p_dto) {
                        // work here
                    });

                m_scan_yara->scan(
                    task.buf,
                    [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                        // work here
                    });
                TRY_END()
                CATCH(security::av::clamav::exception::Scan,
                      { m_server->log->error("Erro ClamAV: {}", e.what()); })
                CATCH(security::yara::exception::Scan,
                      { m_server->log->error("Erro YARA: {}", e.what()); })

                lock.lock();
            }
        }
    }

    void Analysis::scan()
    {
        m_map.add_route("/scan", [&]() {
            m_web_scan = std::make_unique<server::gateway::web::Web>();
            m_web_scan->setup(
                &*m_server,
                BASE_ANALYSIS "/scan",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    if (!req.body.empty() &&
                        req.body.size() >= min_binary_size) {
                        record::EnqueueTask task{0, std::move(req.body)};

                        TRY_BEGIN()
                        Analysis::enqueue_scan(task);
                        TRY_END()
                        CATCH(exception::ParcialAbort,
                              return crow::response{server::gateway::responses::
                                                        InternalServerError()
                                                            .code()};)

                        auto accept =
                            server::gateway::responses::Accepted().add_field(
                                "task_id", task.id);

                        return crow::response{accept.code(),
                                              "application/json",
                                              accept.tojson().tostring()};
                    }

                    auto bad_requests =
                        server::gateway::responses::BadRequests().add_field(
                            "details",
                            fmt::format("File too small for scan minimal {}b",
                                        min_binary_size));

                    return crow::response{bad_requests.code(),
                                          "application/json",
                                          bad_requests.tojson().tostring()};
                });
        });
    }

    void Analysis::scan_av_clamav()
    {
        m_map.add_route("/scan/av/clamav", [&]() {
            m_web_scan_av_clamav =
                std::make_unique<server::gateway::web::Web>();
            m_web_scan_av_clamav->setup(
                &*m_server,
                BASE_ANALYSIS "/scan/av/clamav",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    parser::Json json;

                    TRY_BEGIN()
                    m_scan_av_clamav->scan(
                        req.body,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            json = std::move(m_scan_av_clamav->dto_json(p_dto));
                        });
                    TRY_END()
                    CATCH(security::av::clamav::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)

                    auto connected =
                        server::gateway::responses::Connected().add_field(
                            "clamav", json);

                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }

    void Analysis::scan_yara()
    {
        m_map.add_route("/scan/yara", [&]() {
            m_web_scan_yara = std::make_unique<server::gateway::web::Web>();
            m_web_scan_yara->setup(
                &*m_server,
                BASE_ANALYSIS "/scan/yara",
                [&](const crow::request &req) -> crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    parser::Json json;
                    TRY_BEGIN()
                    m_scan_yara->scan(
                        req.body,
                        [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                            json = std::move(m_scan_yara->dto_json(p_dto));
                        });
                    TRY_END()
                    CATCH(security::yara::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)

                    auto connected =
                        server::gateway::responses::Connected().add_field(
                            "yara", json);

                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }

} // namespace engine::bridge::endpoints::analysis
