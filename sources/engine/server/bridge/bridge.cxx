#include <cstdint>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    namespace server
    {
        Bridge::Bridge(Server &p_server) : SERVER_INSTANCE(p_server)
        {
            m_analysis = std::make_unique<bridge::Analysis>(SERVER_INSTANCE);
            m_data = std::make_unique<bridge::Data>(SERVER_INSTANCE);
            m_rev = std::make_unique<bridge::Rev>(SERVER_INSTANCE);
            m_parser = std::make_unique<bridge::Parser>(SERVER_INSTANCE);
            m_root = std::make_unique<bridge::Root>(SERVER_INSTANCE);
        }

        Bridge::~Bridge()
        {
        }

        void Bridge::load()
        {
            LOG(SERVER_INSTANCE.get_log(), info, "Loading Gateways ... ");

            TRY_BEGIN()

            m_root->load();
            m_data->load();
            m_parser->load();
            m_rev->load();
            m_analysis->load();

            TRY_END()
            CATCH(std::bad_alloc, {
                LOG(SERVER_INSTANCE.get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::runtime_error, {
                LOG(SERVER_INSTANCE.get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::exception, {
                LOG(SERVER_INSTANCE.get_log(), warn, "{}", e.what());
                throw exception::ParcialAbort(e.what());
            })
        }
    } // namespace server
} // namespace engine