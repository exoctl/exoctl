#include <cstdint>
#include <engine/crowapp/bridge/bridge.hxx>
#include <engine/crowapp/exception.hxx>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>

namespace engine
{
    namespace crowapp
    {
        Bridge::Bridge(CrowApp &p_crowapp) : m_crowapp(p_crowapp)
        {
            m_analysis = std::make_unique<bridge::Analysis>(m_crowapp);
            m_data = std::make_unique<bridge::Data>(m_crowapp);
            m_rev = std::make_unique<bridge::Rev>(m_crowapp);
            m_parser = std::make_unique<bridge::Parser>(m_crowapp);
        }

        Bridge::~Bridge()
        {
        }

        void Bridge::load()
        {
            LOG(m_crowapp.get_log(), info, "Loading Gateways ... ");

            TRY_BEGIN()

            m_data->load();
            m_parser->load();
            m_rev->load();
            m_analysis->load();

            TRY_END()
            CATCH(std::bad_alloc, {
                LOG(m_crowapp.get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::runtime_error, {
                LOG(m_crowapp.get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::exception, {
                LOG(m_crowapp.get_log(), warn, "{}", e.what());
                throw exception::ParcialAbort(e.what());
            })
        }
    } // namespace crowapp
} // namespace engine