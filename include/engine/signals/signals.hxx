#pragma once

#include <csignal>
#include <engine/interfaces/ibind.hxx>
#include <functional>

namespace engine::signals
{
    /**
     * @brief class responable for get signals received to CPU
     *
     */
    class Signals
    {
      public:
        Signals() = default;
        ~Signals() = default;

        const bool receive(const int,
                           std::function<void(int, siginfo_t *, void *)>);
    };
} // namespace engine::signals