#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>

namespace engine
{
    namespace bridge
    {
        std::shared_ptr<bridge::endpoints::Plugins> Bridge::plugins;
        std::shared_ptr<bridge::endpoints::Parser> Bridge::parser(
            std::make_shared<bridge::endpoints::Parser>());
        std::shared_ptr<bridge::endpoints::Reverse> Bridge::reverse(
            std::make_shared<bridge::endpoints::Reverse>());
        std::shared_ptr<bridge::endpoints::Data> Bridge::data(
            std::make_shared<bridge::endpoints::Data>());
        std::shared_ptr<bridge::endpoints::Analysis> Bridge::analysis(
            std::make_shared<bridge::endpoints::Analysis>());

        void Bridge::setup(server::Server &p_server)
        {
            m_server = &p_server;

            reverse->setup(*m_server);
            analysis->setup(*m_server);
            data->setup(*m_server);
            parser->setup(*m_server);
            plugins = std::make_shared<bridge::endpoints::Plugins>(*m_server);
        }

        void Bridge::load()
        {
            m_server->log->info("Loading Defaults Gateways ...");

            TRY_BEGIN()

            data->load();
            parser->load();
            reverse->load();
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