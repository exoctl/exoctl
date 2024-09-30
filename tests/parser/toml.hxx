#pragma once
          
#include <engine/parser/toml.hxx>
#include <gtest/gtest.h>       
        
class TomlTest : public ::testing::Test
{       
  protected:
    void SetUp() override      
    { 
        toml = new Parser::Toml();
        toml->toml_parser_file("./configuration.toml");
    }
    
    void TearDown() override   
    {   
        delete toml;
    } 
    
    Parser::Toml *toml;          
};  
