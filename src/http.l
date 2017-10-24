%option noyywrap

%{

#include "http.tab.h"

%}

method [A-Z]+
requesttarget (\/|([\/](?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-a-zA-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-a-zA-Z0-9+&@#\/%=~_|$?!:,.]*\)|[a-zA-Z0-9+&@#\/%=~_|$])))
httpversion (HTTP\/1\.0|HTTP\/1\.1){1}
requestline {method}[ ]{requesttarget}[ ]{httpversion}
fieldname [a-zA-Z][a-zA-Z0-9\-]*
fieldvalue (?:[\x20-\x7E\x80-\xFF](?:[ \t]+[\x20-\x7E\x80-\xFF])?)*
headerfield {fieldname}[:]{fieldvalue}


%%

"\r\n"                      { return CRLF; }

{requestline}               { return requestline; }

{headerfield}               { return headerfield; }

. return yytext[0];

%%