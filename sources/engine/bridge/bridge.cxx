#include <engine/bridge/exception.hxx>
#include <engine/bridge/bridge.hxx>

namespace engine
{
    namespace bridge
    {
        std::shared_ptr<bridge::endpoints::Plugins> Bridge::plugins;
        std::shared_ptr<bridge::endpoints::Analysis> Bridge::analysis(
            std::make_shared<bridge::endpoints::Analysis>());

        void Bridge::setup(server::Server &p_server)
        {
            m_server = &p_server;

            analysis->setup(*m_server);
            plugins = std::make_shared<bridge::endpoints::Plugins>(*m_server);
        }

        void Bridge::load()
        {
            m_server->log->info("Loading Defaults Bridges...");

            TRY_BEGIN()

            analysis->load();
            plugins->load();

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
    } // namespace bridge
} // namespace engine