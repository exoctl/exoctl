#include <cstdint>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    namespace server
    {
        void Bridge::setup(Server &p_server)
        {
            m_server = &p_server;
            m_analysis =
                std::make_unique<bridge::endpoints::Analysis>(*m_server);
            m_data = std::make_unique<bridge::endpoints::Data>(*m_server);
            m_rev = std::make_unique<bridge::endpoints::Rev>(*m_server);
            m_parser = std::make_unique<bridge::endpoints::Parser>(*m_server);
#ifdef ENGINE_PRO
            m_plugins = std::make_unique<bridge::endpoints::Plugins>(*m_server);
#endif
        }
#ifdef ENGINE_PRO
        void Bridge::register_plugins()
        {
            m_data->register_plugins();
            m_analysis->register_plugins();
        }
#endif
        void Bridge::load()
        {
            m_server->log->info("Loading Gateways ... ");

            TRY_BEGIN()

            m_data->load();
            m_parser->load();
            m_rev->load();
            m_analysis->load();
#ifdef ENGINE_PRO
            m_plugins->load();
#endif

            TRY_END()
            CATCH(std::bad_alloc, {
                m_server->log->error("{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::runtime_error, {
                m_server->log->error("{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::exception, {
                m_server->log->warn("{}", e.what());
                throw exception::ParcialAbort(e.what());
            })
        }
    } // namespace server
} // namespace engine