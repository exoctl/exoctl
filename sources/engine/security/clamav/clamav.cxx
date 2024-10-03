#include <engine/memory.hxx>
#include <engine/security/clamav/clamav.hxx>
#include <engine/security/clamav/clamav_exception.hxx>
#include <memory.h>

namespace Security
{
    Clamav::Clamav() : m_engine(nullptr), m_rules_loaded_count(0)
    {
        if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
            throw ClamavException::Initialize(
                "cl_init() : failed to initialize clamav library.");
        }

        m_engine = cl_engine_new();
    }

    const cl_error_t Clamav::clamav_set_db_rule_fd(
        const std::string &p_path, unsigned int p_dboptions) const
    {
        return cl_load(
            p_path.c_str(), m_engine, m_rules_loaded_count, p_dboptions);
    }

    const void Clamav::clamav_scan_bytes(
        const std::string &p_buffer,
        const std::function<void(Cl::Structs::Data *)> &p_callback,
        cl_scan_options *p_scanoptions)
    {
        struct Cl::Structs::Data *data = static_cast<struct Cl::Structs::Data *>(
            alloca(sizeof(struct Cl::Structs::Data)));

        data->clamav_virname = "";
        data->clamav_math_status = cl_scanfile(p_buffer.c_str(),
                    &data->clamav_virname,
                    NULL,
                    m_engine,
                    p_scanoptions);

        p_callback(data);
    }

    void Clamav::clamav_load_rules(const std::function<void()> &p_callback)
    {
        if (!IS_NULL(p_callback)) {
            p_callback();

            cl_error_t ret = cl_engine_compile(m_engine);
            if (ret != CL_SUCCESS) {
                throw ClamavException::LoadRules(
                    "cl_engine_compile() : failed to compile clamav engine: " +
                    std::string(cl_strerror(ret)));
            }
        }
    }

    Clamav::~Clamav()
    {
        if (!IS_NULL(m_engine))
            cl_engine_free(m_engine);
    }
} // namespace Security