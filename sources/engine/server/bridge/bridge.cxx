#include <cstdint>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/bridge/_/crow/crow.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    namespace server
    {
        void Bridge::setup(Server &p_server)
        {
            m_server = &p_server;
            m_root = std::make_unique<bridge::Root>(*m_server);
            m_analysis = std::make_unique<bridge::Analysis>(*m_server);
            m_data = std::make_unique<bridge::Data>(*m_server);
            m_rev = std::make_unique<bridge::Rev>(*m_server);
            m_parser = std::make_unique<bridge::Parser>(*m_server);
        }
#ifdef ENGINE_PRO
        void Bridge::register_plugins()
        {
            engine::server::bridge::_::Crow::plugins();
            engine::server::bridge::gateway::Web::plugins();

            m_data->register_plugins();
            m_analysis->register_plugins();
        }
#endif
        void Bridge::load()
        {
            LOG(m_server->get_log(), info, "Loading Gateways ... ");

            TRY_BEGIN()

            m_root->load();
            m_data->load();
            m_parser->load();
            m_rev->load();
            m_analysis->load();

            TRY_END()
            CATCH(std::bad_alloc, {
                LOG(m_server->get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::runtime_error, {
                LOG(m_server->get_log(), error, "{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::exception, {
                LOG(m_server->get_log(), warn, "{}", e.what());
                throw exception::ParcialAbort(e.what());
            })
        }
    } // namespace server
} // namespace engine