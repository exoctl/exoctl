#pragma once

#include <crow.h>
#include <engine/crowapp/crowapp.hxx>
#include <functional>
#include <string>

namespace crowapp
{
    namespace bridge
    {
        template <typename... Args> class Web
        {
          public:
            using on_request_callback =
                std::function<crow::response(const crow::request &, Args...)>;

            Web(CrowApp &p_crow,
                const std::string &p_url,
                on_request_callback on_request)
                : m_crow(p_crow), m_url(p_url), m_on_request(on_request)
            {
                LOG(m_crow.crow_get_log(),
                    info,
                    "Creating HTTP route for URL: '{}'",
                    m_url);

                m_crow.crow_get_app().route_dynamic(m_url)(m_on_request);
                m_crow.crow_get_app().validate();
            }

            ~Web()
            {
            }

          private:
            CrowApp &m_crow;
            std::string m_url;
            on_request_callback m_on_request;
        };
    } // namespace bridge
} // namespace crowapp