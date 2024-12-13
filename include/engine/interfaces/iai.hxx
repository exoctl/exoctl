#pragma once

#include <cstdarg>
#include <string>

namespace engine
{
    namespace interface
    {
        class IAi
        {
          public:
            IAi() {};
            virtual ~IAi() {};

            virtual const bool load_model(const char *p_path, ...) = 0;
        };
    } // namespace interface
} // namespace engine