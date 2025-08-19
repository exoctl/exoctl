#pragma once

#include <soci/soci.h>

namespace engine::database
{
    using Soci = soci::session;
    using SociError = soci::soci_error;
    using SociIndicator = soci::indicator;
    using SociValues = soci::values;
} // namespace engine::database
