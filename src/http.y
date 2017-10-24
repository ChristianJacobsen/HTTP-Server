%{

#include <stdio.h>
#include <stdbool.h>

int yylex();
int yyerror(char *s);

extern bool VALID;

%}

%token SP
%token CRLF

// %token method
// %token requesttarget
// %token HTTPversion

// requestline:

//     method SP requesttarget SP HTTPversion CRLF
%token requestline

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

sheaderfield:

    sheaderfield headerfield CRLF

    | ;

%%

int yyerror(char *s)
{
    if (s == NULL)
    {
        VALID = false;
    }
    
    VALID = false;
    return 0;
}