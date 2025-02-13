#pragma once

#include <csignal>
#include <engine/interfaces/ibind.hxx>
#include <functional>

namespace engine::emergency
{
    /**
     * @brief class responable for get signals received to CPU
     *
     */
    class Emergency
    {
      public:
        Emergency() = default;
        ~Emergency() = default;

        const bool receive_signal(
            const int, std::function<void(int, siginfo_t *, void *)>);
    };
} // namespace engine::emergency