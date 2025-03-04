#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>

namespace engine
{
    namespace bridge
    {
#ifdef ENGINE_PRO
        std::shared_ptr<bridge::endpoints::Plugins> Bridge::plugins;
#endif
        std::shared_ptr<bridge::endpoints::Parser> Bridge::parser;
        std::shared_ptr<bridge::endpoints::Reverse> Bridge::reverse;
        std::shared_ptr<bridge::endpoints::Data> Bridge::data;
        std::shared_ptr<bridge::endpoints::Analysis> Bridge::analysis;

        Bridge::Bridge()
        {
        }

        void Bridge::setup(server::Server &p_server)
        {
            m_server = &p_server;

            analysis = std::make_shared<bridge::endpoints::Analysis>();
            data = std::make_shared<bridge::endpoints::Data>();

            analysis->setup(*m_server);
            data->setup(*m_server);

            reverse = std::make_shared<bridge::endpoints::Reverse>(*m_server);
            parser = std::make_shared<bridge::endpoints::Parser>(*m_server);
#ifdef ENGINE_PRO
            plugins = std::make_shared<bridge::endpoints::Plugins>(*m_server);
#endif
        }

        void Bridge::load()
        {
            m_server->log->info("Loading Gateways ... ");

            TRY_BEGIN()

            data->load();
            parser->load();
            reverse->load();
            analysis->load();
#ifdef ENGINE_PRO
            plugins->load();
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
    } // namespace bridge
} // namespace engine