#pragma once

#include <crow/middlewares/session.h>

namespace engine
{
    namespace crowapp
    {
        using Session = crow::SessionMiddleware<crow::InMemoryStore>;
    }
} // namespace engine