/**
	= "200"   ; OK
	| "201"   ; Created
	| "202"   ; Accepted
	| "204"   ; No Content
	| "301"   ; Moved Permanently
	| "302"   ; Moved Temporarily
	| "304"   ; Not Modified
	| "400"   ; Bad Request
	| "401"   ; Unauthorized
	| "403"   ; Forbidden
	| "404"   ; Not Found
	| "500"   ; Internal Server Error
	| "501"   ; Not Implemented
	| "502"   ; Bad Gateway
	| "503"   ; Service Unavailable
*/
const char * ERRSTR_BAD_REQUEST =
	"HTTP/1.0 400 BAD REQUEST\r\n"
	"Content-type: text/html\r\n"
	"\r\n"
	"<P>Your browser sent a bad request, "
		"such as a POST without a Content-Length.\r\n";	

const char * ERRSTR_CANNOT_EXECUTE =
	"HTTP/1.0 500 Internal Server Error\r\n"
	"Content-type: text/html\r\n"
	"\r\n"
	"<P>Error prohibited CGI execution.</P>\r\n";


const char * ERRSTR_NOT_FOUND =
	"HTTP/1.0 404 NOT FOUND\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<HTML><BODY><P>The server could not fulfill "
	"your request because the resource specified "
	"is unavailable or nonexistent.</P> "
	"</BODY></HTML>\r\n";

const char * ERRSTR_UNIMPLEMENTED =
	"HTTP/1.0 501 Method Not Implemented\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<HTML><HEAD><TITLE>Method Not Implemented</TITLE></HEAD>\r\n"
	"<BODY><P>HTTP request method not supported.</P></BODY></HTML>\r\n";
