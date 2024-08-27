#include <engine/crow/crow_exception.hxx>

namespace Crow
{
namespace CrowException
{
Abort::Abort(const std::string &p_message) : BaseException(p_message) {}
} // namespace CrowException
} // namespace Crow
