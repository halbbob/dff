%{

#include "typeparser.hpp"
#include "parserparam.hpp"

  extern int yyerror(const char *msg);

  /**
   * 0 : nothing
   * 3 : everything
   */
#define DEBUG_LEVEL     2
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
%token <str> TIDENTIFIER TSTRING TTIMESTAMP TTRUE TFALSE
%token <number> TNUMBER THEXNUMBER

/* delimiter tokens */
%token <token> TCOMMA TLPAREN TRPAREN TDOT TLBRACKET TRBRACKET

/* comparison tokens */
%token <token> TEQ TNEQ TLT TGT TLTE TGTE


%type <comp> comp_operators

%type <node> expr size_cmp mime_cmp name_cmp time_cmp

%type <numlist> number_list

%type <timelist> time_list

%type <strlist> string_list processor_args

%type <proc> processor

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
| mime_cmp
| name_cmp
| time_cmp
;

size_cmp : TSIZE comp_operators TNUMBER {$$ = new SizeCmp($2, $3)}
| TSIZE TIN TLBRACKET number_list TRBRACKET {$$ = new SizeCmp(CmpOperator::EQ, $<numlist>4)}
| TSIZE TNOT TIN TLBRACKET number_list TRBRACKET {$$ = new SizeCmp(CmpOperator::NEQ, $<numlist>5)}
;

mime_cmp : TMIME TEQ TSTRING {$$ = new MimeCmp(CmpOperator::EQ, $3)}
| TMIME TNEQ TSTRING {$$ = new MimeCmp(CmpOperator::NEQ, $3)}
| TMIME TIN TLBRACKET string_list TRBRACKET {$$ = new MimeCmp(CmpOperator::EQ, $<strlist>4)}
| TMIME TNOT TIN TLBRACKET string_list TRBRACKET {$$ = new MimeCmp(CmpOperator::NEQ, $<strlist>5)}
;

name_cmp : TNAME TEQ processor {$$ = new NameCmp(CmpOperator::EQ, $3); DEBUG(INFO, "name == cmp\n")}
| TNAME TNEQ processor {$$ = new NameCmp(CmpOperator::NEQ, $3); DEBUG(INFO, "name != cmp\n")}
;

time_cmp : TTIME comp_operators TTIMESTAMP {$$ = new TimeCmp($2, new vtime(*$3)); delete $3}
| TTIME comp_operators TNUMBER {$$ = new TimeCmp($2, new vtime($3, 0))}
| TTIME TIN TLBRACKET time_list TRBRACKET {$$ = new TimeCmp(CmpOperator::EQ, $4)}
| TTIME TNOT TIN TLBRACKET time_list TRBRACKET {$$ = new TimeCmp(CmpOperator::NEQ, $5)}
;

 time_list : TNUMBER {$$ = new TimeList(); $$->push_back(new vtime($1, 0))}
| TTIMESTAMP {$$ = new TimeList(); $$->push_back(new vtime(*$1)); delete $1}
| time_list TCOMMA TNUMBER {$<timelist>1->push_back(new vtime($3, 0))}
| time_list TCOMMA TTIMESTAMP {$<timelist>1->push_back(new vtime(*$3)); delete $1}
;

number_list: TNUMBER {$$ = new NumberList(); $$->push_back($1); DEBUG(INFO, "numeric list with 1 item")}
| number_list TCOMMA TNUMBER {$<numlist>1->push_back($3); DEBUG(INFO, "numeric list with several items")}
;

string_list : TSTRING {$$ = new StringList(); $$->push_back($1)}
| string_list TCOMMA TSTRING {$<strlist>1->push_back($3)}
;

processor: TIDENTIFIER TLPAREN processor_args TRPAREN {$$ = new Processor($1, $3); DEBUG(INFO, "New method call\n"); }
;

processor_args : TSTRING { $$ = new StringList(); $$->push_back($1); DEBUG(INFO, "Init parsing processor arguments\n"); }
| processor_args TCOMMA TIDENTIFIER { $<strlist>1->push_back($3); DEBUG(INFO, "parsing processor arguments\n"); }
;

comp_operators: TEQ { $$ = CmpOperator::EQ; }
| TNEQ { $$ = CmpOperator::NEQ; }
| TGT { $$ = CmpOperator::GT; }
| TGTE { $$ = CmpOperator::GTE; }
| TLT { $$ = CmpOperator::LT; }
| TLTE { $$ = CmpOperator::LTE; }
;

%%
