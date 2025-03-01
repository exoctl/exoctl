#pragma once

#include <cstdarg>
#include <string>

namespace engine::interface
{
    class IAi
    {
      public:
        IAi() = default;
        virtual ~IAi() = default;

        virtual auto load_model_file(const char *p_path, ...) -> const bool = 0;
    };
} // namespace engine::interface
