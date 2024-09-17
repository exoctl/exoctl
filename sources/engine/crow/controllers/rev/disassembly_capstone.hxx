#pragma once

#include <engine/dto/dto.hxx>
#include <include/engine/disassembly/capstone/capstone.hxx>

namespace Controllers
{
    namespace Rev
    {
        class Capstone : public DTO::DTOBase
        {
          public:
            Capstone(const cs_arch, const cs_mode);
            ~Capstone();

            void capstone_disassembly(const std::string &);

          private:
            Disassembly::Capstone m_capstone;
        };
    } // namespace Rev
} //  namespace Controllers