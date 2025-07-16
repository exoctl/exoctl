#include <engine/signals/signals.hxx>

namespace engine::signals
{
    const bool Signals::receive(
        const int p_signum,
        std::function<void(int, siginfo_t *, void *)> p_handler)
    {
        static std::function<void(int, siginfo_t *, void *)> handler;
        handler = std::move(p_handler);

        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = [](int sig, siginfo_t *info, void *context) {
            handler(sig, info, context);
        };

        sigemptyset(&sa.sa_mask);
        return sigaction(p_signum, &sa, nullptr) != -1;
    }
} // namespace engine::signals