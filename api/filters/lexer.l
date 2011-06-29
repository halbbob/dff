%{
 
#include "typeparser.hpp"
#include "parser.hpp"

/* wrapper to ease token association with variable in typeParser union */
#define SAVE_STRING yylval->str = new std::string(yytext, yyleng)
#define SAVE_TOKEN yylval->token = new std::string(yytext, yyleng)
%}
 
%option reentrant noyywrap never-interactive nounistd
%option bison-bridge

COMMA	    ","
LPAREN      "("
RPAREN      ")"
LBRACKET    "["
RBRACKET    "]"
AND         "and"
OR	    "or"
CONTAINS    "contains"
IN	    "in"
EQ	     "=="
NEQ         "!="
GT          ">"
GTE         ">="
LT          "<"
LTE         "<="
TRUE	    "True"
FALSE	    "False"
IDENTIFIER  [a-zA-Z]+
STRING	    \"(\\.|[^\\"])*\"
NUMBER      [0-9]+
WS          [ \r\n\t]*
TIMESTAMP   [0-9]{4,4}("-"[0-9]{2,2}){2,2}"T"[0-9]{2,2}(":"[0-9]{2,2}){2,2}

%%

{WS}            { /* Skip blanks. */ }
{NUMBER}        { SAVE_STRING; return TNUMBER; }

{COMMA}		{ SAVE_TOKEN; return TCOMMA; }
{LPAREN}        { SAVE_TOKEN; return TLPAREN; }
{RPAREN}        { SAVE_TOKEN; return TRPAREN; }
{LBRACKET}      { SAVE_TOKEN; return TLBRACKET; }
{RBRACKET}      { SAVE_TOKEN; return TRBRACKET; }
{AND}		{ SAVE_TOKEN; return TAND; }
{OR}		{ SAVE_TOKEN; return TOR; }
{EQ}		{ SAVE_TOKEN; return TEQ; }
{NEQ}		{ SAVE_TOKEN; return TNEQ; }
{GT}		{ SAVE_TOKEN; return TGT; }
{GTE}		{ SAVE_TOKEN; return TGTE; }
{LT}		{ SAVE_TOKEN; return TLT; }
{LTE}		{ SAVE_TOKEN; return TLTE; }
{IN}		{ SAVE_TOKEN; return TIN; }
{CONTAINS}	{ SAVE_TOKEN; return TCONTAINS; }
{TRUE}		{ SAVE_STRING; return TTRUE; }
{FALSE}		{ SAVE_STRING; return TFALSE; }
{IDENTIFIER}	{ SAVE_STRING; return TIDENTIFIER;}
{STRING}	{ SAVE_STRING; return TSTRING; }
{TIMESTAMP}	{ SAVE_STRING; return TTIMESTAMP; }
.               {  }

%%

int yyerror(const char *msg) { fprintf(stderr,"Error:%s\n",msg); return 0; }
