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
%token <str> TNAME TDATA TMIME TTIME TSIZE TDELETED TFILE

/* logical tokens */
%token TAND TOR

/* container tokens */
%token TCONTAIN TIN TNOT

/* value tokens */
%token <str> TIDENTIFIER TSTRING TTIMESTAMP TTRUE TFALSE
%token <number> TNUMBER THEXNUMBER

/* delimiter tokens */
%token TCOMMA TLPAREN TRPAREN TDOT TLBRACKET TRBRACKET

/* comparison tokens */
%token TEQ TNEQ TLT TGT TLTE TGTE

%type <str> numeric_ident string_ident boolean_ident

%type <comp> comp_operators

%type <node> expr numeric_filter string_filter boolean_filter time_filter

%type <numlist> number_list

%type <timelist> time_list

%type <strlist> string_list processor_args

%type <proc> processor

%type <boolean>	boolean_value

/* %type <args> processor_args list_args */
/* exprlist --> ptr in typeParser union | call_args --> rule defines below */

%%
 
input: 
expr { ((parserParam*)data)->root = $1; }
;

expr: expr TAND expr { $$ = new Logical( $1, Logical::AND, $3 ); }
| expr TOR expr { $$ = new Logical( $1, Logical::OR, $3 ); }
| TLPAREN expr TRPAREN { $$ = $2; }
| numeric_filter
| string_filter
| boolean_filter
;

numeric_filter: numeric_ident comp_operators TNUMBER { $$ = new NumericFilter(*$1, $2, $3); delete $1; }
| numeric_ident TIN TLBRACKET number_list TRBRACKET { $$ = new NumericFilter(*$1, CmpOperator::EQ, *$<numlist>4); delete $1; delete $4; }
| numeric_ident TNOT TIN TLBRACKET number_list TRBRACKET { $$ = new NumericFilter(*$1, CmpOperator::NEQ, *$<numlist>5); delete $1; delete $5; }
| TSTRING comp_operators TNUMBER { $$ = new NumericFilter(*$1, $2, $3); delete $1; }
| TSTRING TIN TLBRACKET number_list TRBRACKET { $$ = new NumericFilter(*$1, CmpOperator::EQ, *$<numlist>4); delete $1; delete $4; }
| TSTRING TNOT TIN TLBRACKET number_list TRBRACKET { $$ = new NumericFilter(*$1, CmpOperator::NEQ, *$<numlist>5); delete $1; delete $5; }
;

numeric_ident: TSIZE { $$ = $1; }
;

string_filter: TSTRING TEQ TSTRING { $$ = new StringFilter(*$1, CmpOperator::EQ, *$3); delete $1; delete $3; }
| TSTRING TNEQ TSTRING { $$ = new StringFilter(*$1, CmpOperator::NEQ, *$3); delete $1; delete $3; }
| TSTRING TEQ processor { $$ = new StringFilter(*$1, CmpOperator::EQ, $3); delete $1; }
| TSTRING TNEQ processor { $$ = new StringFilter(*$1, CmpOperator::NEQ, $3); delete $1; }
| TSTRING TIN TLBRACKET string_list TRBRACKET { $$ = new StringFilter(*$1, CmpOperator::EQ, *$4); delete $1; delete $4; }
| TSTRING TNOT TIN TLBRACKET string_list TRBRACKET { $$ = new StringFilter(*$1, CmpOperator::NEQ, *$5); delete $1; delete $5; }
| string_ident TEQ TSTRING { $$ = new StringFilter(*$1, CmpOperator::EQ, *$3); delete $1; delete $3; }
| string_ident TNEQ TSTRING { $$ = new StringFilter(*$1, CmpOperator::NEQ, *$3); delete $1; delete $3; }
| string_ident TEQ processor { $$ = new StringFilter(*$1, CmpOperator::EQ, $3); delete $1; }
| string_ident TNEQ processor { $$ = new StringFilter(*$1, CmpOperator::NEQ, $3); delete $1; }
| string_ident TIN TLBRACKET string_list TRBRACKET { $$ = new StringFilter(*$1, CmpOperator::EQ, *$4); delete $1; delete $4; }
| string_ident TNOT TIN TLBRACKET string_list TRBRACKET { $$ = new StringFilter(*$1, CmpOperator::NEQ, *$5); delete $1; delete $5; }
;

string_ident: TNAME { $$ = $1; }
| TMIME { $$ = $1; }
;

boolean_filter: boolean_ident TEQ boolean_value { $$ = new BooleanFilter(*$1, CmpOperator::EQ, $3); delete $1; }
| boolean_ident TNEQ boolean_value { $$ = new BooleanFilter(*$1, CmpOperator::NEQ, $3); delete $1; }
| TSTRING TEQ boolean_value { $$ = new BooleanFilter(*$1, CmpOperator::EQ, $3); delete $1; }
| TSTRING TNEQ boolean_value { $$ = new BooleanFilter(*$1, CmpOperator::NEQ, $3); delete $1; }
;

boolean_ident: TDELETED { $$ = $1; }
| TFILE { $$ = $1; }
;

boolean_value: TTRUE { $$ = true; }
| TFALSE { $$ = false; }
;

time_filter : TTIME comp_operators TTIMESTAMP { $$ = new TimeFilter(*$1, $2, new vtime(*$3)); delete $1; delete $3; }
| TTIME comp_operators TNUMBER {$$ = new TimeFilter(*$1, $2, new vtime($3, 0)); delete $1; }
| TTIME TIN TLBRACKET time_list TRBRACKET { $$ = new TimeFilter(*$1, CmpOperator::EQ, $4); delete $1; delete $4; }
| TTIME TNOT TIN TLBRACKET time_list TRBRACKET {$$ = new TimeFilter(*$1, CmpOperator::NEQ, $5); delete $1; delete $5; }
| TSTRING comp_operators TTIMESTAMP { $$ = new TimeFilter(*$1, $2, new vtime(*$3)); delete $1; delete $3; }
| TSTRING comp_operators TNUMBER {$$ = new TimeFilter(*$1, $2, new vtime($3, 0)); delete $1; }
| TSTRING TIN TLBRACKET time_list TRBRACKET { $$ = new TimeFilter(*$1, CmpOperator::EQ, $4); delete $1; delete $4; }
| TSTRING TNOT TIN TLBRACKET time_list TRBRACKET {$$ = new TimeFilter(*$1, CmpOperator::NEQ, $5); delete $1; delete $5; }
;

number_list: TNUMBER { $$ = new NumberList(); $$->push_back($1); }
| number_list TCOMMA TNUMBER { $<numlist>1->push_back($3); }
;

string_list : TSTRING { $$ = new StringList(); $$->push_back(*$1); delete $1; }
| string_list TCOMMA TSTRING { $<strlist>1->push_back(*$3); delete $3; }
;

time_list : TNUMBER {$$ = new TimeList(); $$->push_back(new vtime($1, 0))}
| TTIMESTAMP {$$ = new TimeList(); $$->push_back(new vtime(*$1)); delete $1}
| time_list TCOMMA TNUMBER {$<timelist>1->push_back(new vtime($3, 0))}
| time_list TCOMMA TTIMESTAMP {$<timelist>1->push_back(new vtime(*$3)); delete $1}


processor: TIDENTIFIER TLPAREN processor_args TRPAREN { $$ = new Processor(*$1, *$3); delete $1; delete $3; }
;

processor_args : TSTRING { $$ = new StringList(); $$->push_back(*$1); delete $1; }
| processor_args TCOMMA TIDENTIFIER { $<strlist>1->push_back(*$3); delete $3; }
;

comp_operators: TEQ { $$ = CmpOperator::EQ; }
| TNEQ { $$ = CmpOperator::NEQ; }
| TGT { $$ = CmpOperator::GT; }
| TGTE { $$ = CmpOperator::GTE; }
| TLT { $$ = CmpOperator::LT; }
| TLTE { $$ = CmpOperator::LTE; }
;

%%
