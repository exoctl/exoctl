#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>

namespace engine
{
    namespace bridge
    {
        Bridge::Bridge() : m_data(std::make_unique<bridge::endpoints::Data>())
        {
        }

        void Bridge::setup(server::Server &p_server)
        {
            m_server = &p_server;
            m_analysis =
                std::make_unique<bridge::endpoints::Analysis>(*m_server);

            m_data->setup(*m_server);

            m_reverse = std::make_unique<bridge::endpoints::Reverse>(*m_server);
            m_parser = std::make_unique<bridge::endpoints::Parser>(*m_server);
#ifdef ENGINE_PRO
            m_plugins = std::make_unique<bridge::endpoints::Plugins>(*m_server);
#endif
        }

        void Bridge::bind_to_lua(sol::state_view &p_lua)
        {
            p_lua.new_usertype<bridge::Bridge>(
                "Bridge",
                sol::constructors<bridge::Bridge()>(),
#ifdef ENGINE_PRO
                "register_plugins",
                &Bridge::register_plugins,
#endif
                "setup",
                &Bridge::setup,
                "load",
                &Bridge::load);
        }

#ifdef ENGINE_PRO
        void Bridge::register_plugins()
        {
            bridge::endpoints::Data::plugins();
            m_analysis->register_plugins();

            Bridge::bind_to_lua(plugins::Plugins::lua.state);
        }
#endif
        void Bridge::load()
        {
            m_server->log->info("Loading Gateways ... ");

            TRY_BEGIN()

            m_data->load();
            m_parser->load();
            m_reverse->load();
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
    } // namespace bridge
} // namespace engine