%option noyywrap

%{

#include "http.tab.h"

%}

requesttarget [\/](?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-a-zA-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[a-zA-Z0-9+&@#\/%=~_|$])
fieldname [a-zA-Z][a-zA-Z0-9\-]*
fieldvalue (?:[\x20-\x7E\x80-\xFF](?:[ \t]+[\x20-\x7E\x80-\xFF])?)*
headerfield {fieldname}[:]{fieldvalue}

%%

" "                         { return SP; }
"\r\n"                      { return CRLF; }

"GET"                       { return method; }
"HEAD"                      { return method; }
"POST"                      { return method; }

"HTTP/1.0"                  { return HTTPversion; }
"HTTP/1.1"                  { return HTTPversion; }

"/"                         { return requesttarget; }

{requesttarget}             { return requesttarget; }

{headerfield}               { return headerfield; }

. return yytext[0];

%%