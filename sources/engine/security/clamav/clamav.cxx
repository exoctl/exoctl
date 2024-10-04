#include <engine/memory.hxx>
#include <engine/security/clamav/clamav.hxx>
#include <engine/security/clamav/exception.hxx>
#include <fmt/core.h>
#include <memory.h>

namespace security
{
    Clamav::Clamav() : m_engine(nullptr), m_rules_loaded_count(0)
    {
        if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
            throw clamav::exception::Initialize(
                "cl_init() : failed to initialize clamav.");
        }

        if (IS_NULL((m_engine = cl_engine_new()))) {
            throw clamav::exception::Initialize(
                "cl_engine_new() : failed to new engine clamav.");
        }
    }

    void Clamav::clamav_set_db_rule_fd(const std::string &p_path,
                                       unsigned int p_dboptions) const
    {
        const cl_error_t ret = cl_load(
            p_path.c_str(), m_engine, &m_rules_loaded_count, p_dboptions);

        if (ret != CL_SUCCESS) {
            throw clamav::exception::SetDbRules("cl_load() failed load db" +
                                                std::string(cl_strerror(ret)));
        }
    }

    const void Clamav::clamav_scan_fast_bytes(
        const std::string &p_buffer,
        clamav::record::scan::Options p_options,
        const std::function<void(clamav::record::Data *)> &p_callback)
    {
        struct clamav::record::Data *data =
            static_cast<struct clamav::record::Data *>(
                alloca(sizeof(struct clamav::record::Data)));

        struct cl_scan_options scanopts =
            (cl_scan_options){.general = p_options.clamav_dev,
                              .parse = p_options.clamav_parse,
                              .heuristic = p_options.clamav_heuristic,
                              .mail = p_options.clamav_mail,
                              .dev = p_options.clamav_dev};

        const cl_error_t ret = cl_scanfile(p_buffer.c_str(),
                                           &data->clamav_virname,
                                           nullptr,
                                           m_engine,
                                           &scanopts);

        (IS_NULL(data->clamav_virname)) ? data->clamav_virname = ""
                                        : data->clamav_virname;

        data->clamav_math_status = [ret]() {
            switch (ret) {
                case CL_VIRUS:
                    return clamav::type::Scan::clamav_virus;
                case CL_CLEAN:
                    return clamav::type::Scan::clamav_clean;
                default:
                    return clamav::type::Scan::clamav_none;
            }
        }();

        if (!IS_NULL(p_callback)) {
            p_callback(data);
        }
    }

    void Clamav::clamav_load_rules(const std::function<void()> &p_callback)
    {
        if (!IS_NULL(p_callback)) {
            p_callback();
        }

        const cl_error_t ret = cl_engine_compile(m_engine);
        if (ret != CL_SUCCESS) {
            throw clamav::exception::LoadRules(
                "cl_engine_compile() : failed to compile clamav engine: " +
                std::string(cl_strerror(ret)));
        }
    }

    const unsigned int Clamav::clamav_get_rules_loaded_count() const
    {
        return m_rules_loaded_count;
    }

    Clamav::~Clamav()
    {
        if (!IS_NULL(m_engine))
            cl_engine_free(m_engine);
    }
} // namespace security