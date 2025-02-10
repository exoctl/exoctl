#include <engine/dll/dll.hxx>

namespace engine
{
    namespace dll
    {
        const void *Dll::open(const char *p_name, int p_mode)
        {
            return dlopen(p_name, p_mode);
        }

        const int Dll::close(void *p_handle)
        {
            return dlclose(p_handle);
        }

        void Dll::info(void *p_handle,
                       int p_request,
                       const std::function<void(struct link_map &)> &p_callback)
        {
            struct link_map *map;
            if (dlinfo(p_handle, p_request, &map) == 0) {
                while (map) {
                    p_callback(*map);
                    map = map->l_next;
                }
            }
        }
    } // namespace dll
} // namespace engine