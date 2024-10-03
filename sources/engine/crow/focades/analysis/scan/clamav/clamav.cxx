#include <engine/crow/focades/analysis/scan/clamav/clamav.hxx>
#include <engine/memory.hxx>

namespace Focades
{
    namespace Analysis
    {
        namespace Scan
        {
            Clamav::Clamav(Parser::Toml &p_config)
                : m_clamav(), m_config(p_config),
                  m_clamav_default_rules(GET_TOML_TBL_VALUE(
                      p_config, string, "clamav", "default_database"))
            {
            }

            Clamav::~Clamav()
            {
            }

            void Clamav::clamav_load_rules(
                const std::function<void()> &p_callback)
            {
                if (!IS_NULL(p_callback)) {
                    p_callback();
                }

                m_clamav.clamav_load_rules([&]() {
                    if (m_clamav.clamav_set_db_rule_fd(m_clamav_default_rules,
                                                       CL_DB_STDOPT))
                        ;
                });
            }

            void Clamav::clamav_scan_bytes(
                const std::string &p_buffer,
                const std::function<void(Cl::Structs::DTO *)> &p_callback)
            {
                if (!IS_NULL(p_callback)) {
                    struct Cl::Structs::DTO *dto = new Cl::Structs::DTO;
                    m_clamav.clamav_scan_bytes(
                        p_buffer,
                        [&](const Security::Cl::Structs::Data *p_data) {
                            dto->clamav_math_status =
                                p_data->clamav_math_status;
                            dto->clamav_virname = p_data->clamav_virname;
                        });

                    p_callback(dto);
                    delete dto;
                }
            }
            Parser::Json Clamav::clamav_dto_json(Cl::Structs::DTO *p_dto)
            {
                Parser::Json json;

                if (!IS_NULL(p_dto)) {

                    json.json_add_member_string("clamav_virname",
                                                p_dto->clamav_virname);
                    json.json_add_member_int("clamav_math_status",
                                                p_dto->clamav_math_status);
                }

                return json;
            }
        } // namespace Scan
    } // namespace Analysis
} // namespace Focades