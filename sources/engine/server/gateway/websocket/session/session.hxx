#pragma once

#include <crow/middlewares/session.h>

namespace engine
{
    namespace server
    {
        using Session = crow::SessionMiddleware<crow::InMemoryStore>;
    }
} // namespace engine