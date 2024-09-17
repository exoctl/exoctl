#pragma once

#include <engine/exception.hxx>

namespace DTO
{
    namespace DTOException
    {

        class Field : public Exception::ExceptionBase
        {
          public:
            explicit Field(const std::string &);
        };

    } // namespace DTOException
} // namespace DTO