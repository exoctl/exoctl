#include <engine/memory/memory.hxx>
#include <engine/security/av/clamav/clamav.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <fcntl.h>
#include <fmt/core.h>
#include <include/engine/memory/exception.hxx>
#include <memory>
#include <mutex>
#include <unistd.h>

namespace engine::security::av::clamav
{
    Clamav::Clamav() : m_engine(nullptr), rules_loaded_count(0)
    {
        const std::scoped_lock lock(m_mutex);

        if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
            throw clamav::exception::Initialize(
                "cl_init() : failed to initialize clamav.");
        }

        m_engine = cl_engine_new();
        if (IS_NULL(m_engine)) {
            throw clamav::exception::Initialize(
                "cl_engine_new() : failed to new engine clamav.");
        }
    }

    void Clamav::set_db_rule_fd(const std::string &p_path,
                                unsigned int p_dboptions) const
    {
        const std::scoped_lock lock(m_mutex);

        const cl_error_t ret =
            cl_load(p_path.c_str(), m_engine, &rules_loaded_count, p_dboptions);
        if (ret != CL_SUCCESS) {
            throw clamav::exception::SetDbRules("cl_load() failed load db " +
                                                std::string(cl_strerror(ret)));
        }
    }

    void Clamav::scan_bytes(
        const std::string &p_buffer,
        clamav::record::scan::Options p_options,
        const std::function<void(clamav::record::Data *)> &p_callback)
    {
        std::shared_ptr<engine::security::av::clamav::record::Data> data =
            std::make_shared<clamav::record::Data>();
        int fd = -1;

        TRY_BEGIN()
        fd = memory::Memory::fd("tmp_", MFD_ALLOW_SEALING);
        memory::Memory::ftruncate(fd, p_buffer.size());
        memory::Memory::write(fd, p_buffer.data(), p_buffer.size());
        TRY_END()
        CATCH(memory::exception::Fd, {
            throw clamav::exception::Scan(
                "scan_bytes() : Scan failed, error : " + std::string(e.what()));
        })
        CATCH(memory::exception::Write, {
            throw clamav::exception::Scan(
                "scan_bytes() : Scan failed, error : " + std::string(e.what()));
        })
        CATCH(memory::exception::Ftruncate, {
            throw clamav::exception::Scan(
                "scan_bytes() : Scan failed, error : " + std::string(e.what()));
        })

        cl_error_t ret;
        {
            std::scoped_lock lock(m_mutex);
            ret = cl_scandesc(
                fd, "tmp_", &data->virname, nullptr, m_engine, &p_options);
        }

        data->virname = (IS_NULL(data->virname)) ? "" : data->virname;
        data->math_status = [ret]() {
            switch (ret) {
                case CL_VIRUS:
                    return clamav::type::Scan::virus;
                case CL_CLEAN:
                    return clamav::type::Scan::clean;
                default:
                    return clamav::type::Scan::none;
            }
        }();

        memory::Memory::close(fd);

        if (p_callback) {
            p_callback(data.get());
        }
    }

    void Clamav::load_rules()
    {
        const std::scoped_lock lock(m_mutex);
        const cl_error_t ret = cl_engine_compile(m_engine);
        if (ret != CL_SUCCESS) {
            throw clamav::exception::LoadRules(
                "cl_engine_compile() : failed to compile clamav "
                "engine: " +
                std::string(cl_strerror(ret)));
        }
    }

    Clamav::~Clamav()
    {
        const std::scoped_lock lock(m_mutex);
        if (m_engine) {
            cl_engine_free(m_engine);
            m_engine = nullptr;
        }
    }

} // namespace engine::security::av::clamav
