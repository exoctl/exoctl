#include <engine/magic/magic_exception.hxx>
#include <engine/exception.hxx>
#include <string>

namespace Magic
{
namespace MagicException
{

Initialize::Initialize(const std::string &p_message) : BaseException(p_message)
{
}

Finalize::Finalize(const std::string &p_message) : BaseException(p_message) {}

} // namespace DataException
} // namespace Data

