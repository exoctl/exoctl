#include <engine/crow/routes/web/web.hxx>

namespace Crow
{
Web::Web(CrowApp &p_crow,
         const std::string &p_url,
         on_request_callback on_request)
    : m_crow(p_crow), m_url(p_url), m_on_request(on_request)
{
    LOG(m_crow.crow_get_log(),
        info,
        "Creating HTTP route for URL: '{}'",
        m_url);

    m_crow.crow_get_app().route_dynamic(m_url)(m_on_request);
}

Web::~Web() {}
} // namespace Crow
