%{
 
#include "typeparser.hpp"
#include "parser.hpp"

uint64_t		token_to_number(char* str, int len)
{
  uint64_t		res;

  std::istringstream istr(std::string(str, len));
  if (!(istr >> res))
    ;//yyerror("cannot convert string to number");
  return res;
}

uint64_t		token_to_hexnumber(char* str, int len)
{
  uint64_t		res;

  std::istringstream istr(std::string(str, len));
  istr.setf(ios::hex, ios::basefield);
  if (!(istr >> res))
    ;//;yyerror("cannot convert string to number");
  return res;
}


/* wrapper to ease token association with variable in typeParser union */
#define SAVE_STRING yylval->str = new std::string(yytext, yyleng)
#define SAVE_NUMBER yylval->number = token_to_number(yytext, yyleng)
#define SAVE_HEXNUMBER yylval->number = token_to_hexnumber(yytext, yyleng)
%}
 
%option reentrant noyywrap never-interactive nounistd
%option bison-bridge

NAME	    "name"
DATA	    "data"
MIME	    "mime"
TIME	    "time"
SIZE        "size"
DELETED	    "deleted"
FILE	    "file"

AND         "and"
OR	    "or"

CONTAIN     "contain"
IN	    "in"
NOT	    "not"

TRUE	    "true"
FALSE	    "false"

IDENTIFIER  [a-zA-Z]+
STRING	    \"(\\.|[^\\"])*\"
NUMBER      [0-9]+
HEXNUMBER   0[xX][a-fA-F0-9]+
TIMESTAMP   [0-9]{4,4}("-"[0-9]{2,2}){2,2}"T"[0-9]{2,2}(":"[0-9]{2,2}){2,2}
WS          [ \r\n\t]*

COMMA	    ","
LPAREN      "("
RPAREN      ")"
LBRACKET    "["
RBRACKET    "]"
EQ	     "=="
NEQ         "!="
GT          ">"
GTE         ">="
LT          "<"
LTE         "<="

%%

{NAME}		{ SAVE_STRING; return TNAME; }
{DATA}		{ SAVE_STRING; return TDATA; }
{MIME}		{ SAVE_STRING; return TMIME; }
{TIME}		{ SAVE_STRING; return TTIME; }
{SIZE}		{ SAVE_STRING; return TSIZE; }
{DELETED}	{ SAVE_STRING; return TDELETED; }
{FILE}		{ SAVE_STRING; return TFILE; }

{AND}		{ return TAND; }
{OR}		{ return TOR; }

{CONTAIN}	{ return TCONTAIN; }
{IN}		{ return TIN; }
{NOT}		{ return TNOT; }

{TRUE}		{ return TTRUE; }
{FALSE}		{ return TFALSE; }

{IDENTIFIER}	{ SAVE_STRING; return TIDENTIFIER;}
{STRING}	{ SAVE_STRING; return TSTRING; }
{NUMBER}        { SAVE_NUMBER; return TNUMBER; }
{HEXNUMBER}	{ SAVE_HEXNUMBER; return TNUMBER; }
{TIMESTAMP}	{ SAVE_STRING; return TTIMESTAMP; }
{WS}            { /* Skip blanks. */ }

{COMMA}		{ return TCOMMA; }
{LPAREN}        { return TLPAREN; }
{RPAREN}        { return TRPAREN; }
{LBRACKET}      { return TLBRACKET; }
{RBRACKET}      { return TRBRACKET; }

{EQ}		{ return TEQ; }
{NEQ}		{ return TNEQ; }
{GT}		{ return TGT; }
{GTE}		{ return TGTE; }
{LT}		{ return TLT; }
{LTE}		{ return TLTE; }
.               {  }
%%
#include <stdio.h>
int yyerror(const char *msg) { fprintf(stderr,"Error:%s\n",msg); return 0; }
