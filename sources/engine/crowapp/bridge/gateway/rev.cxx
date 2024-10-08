#include <engine/crowapp/bridge/gateway/rev.hxx>

namespace crowapp
{
    namespace bridge
    {
        Rev::Rev(CrowApp &p_crowapp) : m_crowapp(p_crowapp), m_map(BASE_REV)
        {
        }

        Rev::~Rev()
        {
        }

        void Rev::load() const
        {
        }

        void Rev::prepare()
        {
        }
        void Rev::capstone_x64()
        {
        }
        void Rev::capstone_arm64()
        {
        }

    } // namespace bridge
} // namespace crowapp