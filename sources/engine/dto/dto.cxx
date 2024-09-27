#include <engine/dto/dto.hxx>

namespace DTO
{
    DTOBase::~DTOBase()
    {
    }
    DTOBase::DTOBase()
    {
    }

    const Parser::Json DTOBase::dto_to_json() const
    {
        m_json.clear();

        for (const auto &[key, value] : m_fields) {
            std::visit(
                [this, &key](const auto &arg) {
                    if constexpr (std::is_same_v<std::decay_t<decltype(arg)>,
                                                 Parser::Json>) {
                        for (const auto &item : arg) {
                            m_json[key].push_back(item);
                        }
                    } else {
                        m_json[key] = arg;
                    }
                },
                value);
        }

        return m_json;
    }
} // namespace DTO