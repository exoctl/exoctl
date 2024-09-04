#pragma once
      
#include <engine/exception.hxx>
#include <string>              
  
namespace Magic
{     
namespace MagicException        
{ 

class Initialize : public Exception::BaseException 
{ 
  public:                      
    explicit Initialize(const std::string &);
};

class Finalize : public Exception::BaseException
{
  public:
    explicit Finalize(const std::string &);
};

} // namespace DataException
} // namespace Data
