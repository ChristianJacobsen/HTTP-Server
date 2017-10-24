%option noyywrap

%{

#include "http.tab.h"

%}

method [A-Z]+
requesttarget [\/](?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-a-zA-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[a-zA-Z0-9+&@#\/%=~_|$])
httpversion HTTP\/[0-9]+\.[0-9]+
fieldname [a-zA-Z][a-zA-Z0-9\-]*
fieldvalue (?:[\x20-\x7E\x80-\xFF](?:[ \t]+[\x20-\x7E\x80-\xFF])?)*
headerfield {fieldname}[:]{fieldvalue}

%%

" "                         { return SP; }
"\r\n"                      { return CRLF; }

{method}                    { return method; }

{httpversion}               { return HTTPversion; }

"/"                         { return requesttarget; }

{requesttarget}             { return requesttarget; }

{headerfield}               { return headerfield; }

. return yytext[0];

%%