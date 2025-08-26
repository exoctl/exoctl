#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>

namespace engine
{
    namespace bridge
    {
        std::shared_ptr<bridge::endpoints::Plugins> Bridge::plugins;
        std::shared_ptr<bridge::endpoints::analysis::Analysis> Bridge::analysis(
            std::make_shared<bridge::endpoints::analysis::Analysis>());

        void Bridge::setup(server::Server &p_server)
        {
            server_ = &p_server;

            analysis->setup(*server_);
            plugins = std::make_shared<bridge::endpoints::Plugins>(*server_);
        }

        void Bridge::load()
        {
            server_->log->info("Loading Defaults Bridges ...");

            TRY_BEGIN()

            analysis->load();
            plugins->load();

            TRY_END()
            CATCH(std::bad_alloc, {
                server_->log->error("{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::runtime_error, {
                server_->log->error("{}", e.what());
                throw exception::Abort(e.what());
            })
            CATCH(std::exception, {
                server_->log->warn("{}", e.what());
                throw exception::ParcialAbort(e.what());
            })
        }
    } // namespace bridge
} // namespace engine