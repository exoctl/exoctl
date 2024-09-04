#pragma once

#include <ctime>
#include <engine/crypto/sha.hxx>
#include <engine/magic/magic.hxx>
#include <engine/dto.hxx>

namespace Data
{
class Metadata : public DTO::DTOBase
{
  public:
    Metadata();
    ~Metadata();

    const void metadata_parse(const std::string &);

  private:
    const void compute_entropy(const std::string &);
    
    double m_entropy;
    time_t m_current_time;
    Magic::Magic m_magic;
    Crypto::Sha m_sha;
};
} // namespace Data
