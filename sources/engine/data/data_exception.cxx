#include <engine/data/data_exception.hxx>
#include <engine/exception.hxx>
#include <string>

namespace Data
{
namespace DataException
{

Initialize::Initialize(const std::string &p_message) : BaseException(p_message)
{
}

Finalize::Finalize(const std::string &p_message) : BaseException(p_message) {}

} // namespace DataException
} // namespace Data

