%{

#include <stdio.h>
#include <stdbool.h>

int yylex();
int yyerror(char *s);

extern bool VALID;

%}

%token SP
%token CRLF

%token method
%token requesttarget
%token HTTPversion

%token fieldname
%token fieldvalue
%token headerfield

%token messagebody

%%

HTTPmessage:

    requestline sheaderfield CRLF
    {
        VALID = true;
    }

    | ;

requestline:

    method SP requesttarget SP HTTPversion CRLF

sheaderfield:

    sheaderfield headerfield CRLF

    | ;

%%

int yyerror(char *s)
{
    VALID = false;
    return 0;
}