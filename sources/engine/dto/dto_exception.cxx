#include <engine/dto/dto_exception.hxx>

namespace DTO
{
    namespace DTOException
    {
        Field::Field(const std::string &p_message) : ExceptionBase(p_message)
        {
        }
    } // namespace DTOException
} // namespace DTO