/*
 * typeparser.h
 * Definition of the structure used internally by the parser and lexer
 * to exchange data.
 */
 
#ifndef __TYPEPARSER_H__
#define __TYPEPARSER_H__
 
#include "astnodes.hpp"

/**
 * @brief The structure used by flex and bison
 */
typedef union stypeParser
{
  Expression*		expression;
  ArgumentsList*	args;
  Identifier*		identifier;
  Number*		number;
/* following enables to track yyval and yytext */
  std::string*		attrs;
  std::string*	str;
  std::string*	token;
  std::string*	boolean;
  int		comp;
}		typeParser;
 
// define the type for flex and bison
#define YYSTYPE typeParser
 
#endif // __TYPE_PARSER_H__
