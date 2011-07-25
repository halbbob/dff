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
#define SAVE_TOKEN yylval->token = new std::string(yytext, yyleng)
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

TRUE	    "True"
FALSE	    "False"

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

{NAME}		{ return TNAME; }
{DATA}		{ return TDATA; }
{MIME}		{ return TMIME; }
{TIME}		{ return TTIME; }
{SIZE}		{ return TSIZE; }
{DELETED}	{ return TDELETED; }
{FILE}		{ return TFILE; }

{AND}		{ SAVE_TOKEN; return TAND; }
{OR}		{ SAVE_TOKEN; return TOR; }

{CONTAIN}	{ SAVE_TOKEN; return TCONTAIN; }
{IN}		{ SAVE_TOKEN; return TIN; }
{NOT}		{ SAVE_TOKEN; return TNOT; }

{TRUE}		{ SAVE_STRING; return TTRUE; }
{FALSE}		{ SAVE_STRING; return TFALSE; }

{IDENTIFIER}	{ SAVE_STRING; return TIDENTIFIER;}
{STRING}	{ SAVE_STRING; return TSTRING; }
{NUMBER}        { SAVE_NUMBER; return TNUMBER; }
{HEXNUMBER}	{ SAVE_HEXNUMBER; return TNUMBER; }
{TIMESTAMP}	{ SAVE_STRING; return TTIMESTAMP; }
{WS}            { /* Skip blanks. */ }

{COMMA}		{ SAVE_TOKEN; return TCOMMA; }
{LPAREN}        { SAVE_TOKEN; return TLPAREN; }
{RPAREN}        { SAVE_TOKEN; return TRPAREN; }
{LBRACKET}      { SAVE_TOKEN; return TLBRACKET; }
{RBRACKET}      { SAVE_TOKEN; return TRBRACKET; }

{EQ}		{ SAVE_TOKEN; return TEQ; }
{NEQ}		{ SAVE_TOKEN; return TNEQ; }
{GT}		{ SAVE_TOKEN; return TGT; }
{GTE}		{ SAVE_TOKEN; return TGTE; }
{LT}		{ SAVE_TOKEN; return TLT; }
{LTE}		{ SAVE_TOKEN; return TLTE; }
.               {  }
%%
#include <stdio.h>
int yyerror(const char *msg) { fprintf(stderr,"Error:%s\n",msg); return 0; }
