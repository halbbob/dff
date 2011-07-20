%{

#include "typeparser.hpp"
#include "parserparam.hpp"

  extern int yyerror(const char *msg);

  /**
   * 0 : nothing
   * 3 : everything
   */
#define DEBUG_LEVEL     0
#define VERBOSE         3
#define INFO            2
#define CRITICAL        1
#if (!defined(WIN64) && !defined(WIN32))
#define DEBUG(level, str, args...) do {                                        \
    if (DEBUG_LEVEL)                                                             \
      if (level <= DEBUG_LEVEL)                                                  \
	printf("%s:%d\t" str, __FILE__, __LINE__, ##args);                       \
  } while (0)
#else
#define DEBUG(level, str, ...) do {                                            \
    if (DEBUG_LEVEL)                                                             \
      if (level <= DEBUG_LEVEL)                                                  \
	printf("%s:%d\t" str, __FILE__, __LINE__, __VA_ARGS__);                  \
  } while (0)
#endif

 
  %}

/* enables re-entrant api */
%define api.pure

/* operator precedence from lowest to highest */
%left TOR
%left TAND

/* keyword tokens */
%token <token> TNAME TDATA TMIME TTIME TSIZE TDELETED TFILE

/* logical tokens */
%token <token> TAND TOR

/* container tokens */
%token <token> TCONTAIN TIN TNOT

/* value tokens */
%token <str> TSTRING TTIMESTAMP TTRUE TFALSE
%token <number> TNUMBER THEXNUMBER

/* delimiter tokens */
%token <token> TCOMMA TLPAREN TRPAREN TDOT TLBRACKET TRBRACKET

/* comparison tokens */
%token <token> TEQ TNEQ TLT TGT TLTE TGTE


%type <comp> comp_operators

%type <node> expr size_cmp//primary_expression processor

%type <numlist> number_list

/* %type <args> processor_args list_args */
/* exprlist --> ptr in typeParser union | call_args --> rule defines below */

%%
 
input: 
expr { ((parserParam*)data)->root = $1; }
;

expr: expr TAND expr { DEBUG(INFO, "TOKEN_AND\n"); $$ = new Logical( $1, Logical::AND, $3 ); }
| expr TOR expr { DEBUG(INFO, "TOKEN_OR\n"); $$ = new Logical( $1, Logical::OR, $3 ); }
| TLPAREN expr TRPAREN { $$ = $2; }
| size_cmp
/* | TSTRING comp_operators primary_expression {$$ = new Comparison ($<str>1, $2, $3); } */
/* | TSTRING TEQ processor { $$ = new Comparison($<str>1, Comparison::EQ, $3); } */
/* | TSTRING TNEQ processor { $$ = new Comparison($<str>1, Comparison::NEQ, $3); } */
/* | TSTRING TCONTAINS processor { $$ = new Operation(new Identifier($<str>1), $<str>2, $3); } */
/* | TSTRING TIN TLBRACKET list_args TRBRACKET { $$ = new Operation(new Identifier($<str>1), $<token>2, new MethodCall(new std::string("list"), $4)); } */
;

size_cmp : TSIZE comp_operators TNUMBER {$$ = new SizeCmp($2, $<number>3)}
| TSIZE TIN TLBRACKET number_list TRBRACKET {$$ = new SizeCmp(CmpOperator::EQ, $<numlist>4)}
| TSIZE TNOT TIN TLBRACKET number_list TRBRACKET {$$ = new SizeCmp(CmpOperator::NEQ, $<numlist>5)}
;

number_list: TNUMBER {$$ = new NumberList(); $$->push_back($1); DEBUG(INFO, "numeric list with 1 item")}
| number_list TCOMMA TNUMBER {$<numlist>1->push_back($3); DEBUG(INFO, "numeric list with several items")}
;

/* ident: TIDENTIFIER { $$ = new Identifier($<str>1); } */
/* ; */

comp_operators: TEQ { $$ = CmpOperator::EQ; }
| TNEQ { $$ = CmpOperator::NEQ; }
| TGT { $$ = CmpOperator::GT; }
| TGTE { $$ = CmpOperator::GTE; }
| TLT { $$ = CmpOperator::LT; }
| TLTE { $$ = CmpOperator::LTE; }
;

/* primary_expression: TTRUE {$$ = new Identifier($<str>1); DEBUG(INFO, "primary_expr --> true\n"); } */
/* | TFALSE {$$ = new Identifier($<str>1); DEBUG(INFO, "primary_expr --> false\n"); } */
/* | TSTRING {$$ = new Identifier($<str>1); DEBUG(INFO, "primary_expr --> string\n"); } */
/* | TTIMESTAMP {$$ = new Identifier($<str>1); DEBUG(INFO, "primary_expr --> timestamp\n"); } */
/* | TNUMBER { $$ = new Identifier($<str>1); DEBUG(INFO, "primary_expr --> number\n"); } */
/* ; */

/* processor: TIDENTIFIER TLPAREN processor_args TRPAREN {$$ = new MethodCall($<str>1, $3); DEBUG(INFO, "New method call\n"); } */
/* ; */


/* processor_args : primary_expression { $$ = new ArgumentsList(); $$->push_back($1); DEBUG(INFO, "Init parsing processor arguments\n"); } */
/* | processor_args TCOMMA primary_expression { $<args>1->push_back($3); DEBUG(INFO, "parsing processor arguments\n"); } */
/* | processor_args TCOMMA ident { $<args>1->push_back($3); DEBUG(INFO, "parsing processor arguments\n"); } */
/* ; */

/* list_args : primary_expression { $$ = new ArgumentsList(); $$->push_back($1); } */
/* | processor { $$ = new ArgumentsList(); $$->push_back($1); } */
/* | list_args TCOMMA primary_expression  { $<args>1->push_back($3); DEBUG(INFO, "parsing processor arguments\n"); } */
/* | list_args TCOMMA ident { $<args>1->push_back($3); DEBUG(INFO, "parsing processor arguments\n"); } */
/* | list_args TCOMMA processor { $<args>1->push_back($3); } */
/* ; */
%%
