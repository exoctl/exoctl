#pragma once
      
#include <engine/exception.hxx>
#include <string>              
  
namespace Magic
{     
namespace MagicException        
{ 

class Initialize : public Exception::ExceptionBase 
{ 
  public:                      
    explicit Initialize(const std::string &);
};

class Finalize : public Exception::ExceptionBase
{
  public:
    explicit Finalize(const std::string &);
};

} // namespace DataException
} // namespace Data
