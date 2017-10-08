#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>

bool VALID = false;

extern void yyparse();

int main(int argc, char **argv)
{
    extern FILE *yyin;
    yyin = fopen("html.txt", "r");
    yyparse();

    fflush(stdout);
    printf("HTTP IS: %s\n", (VALID ? "Valid" : "Invalid"));

    return 0;
}