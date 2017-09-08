/**
 *
	fastcgi_param   QUERY_STRING            $query_string;
	fastcgi_param   REQUEST_METHOD          $request_method;
	fastcgi_param   CONTENT_TYPE            $content_type;
	fastcgi_param   CONTENT_LENGTH          $content_length;

	fastcgi_param   SCRIPT_FILENAME         $document_root$fastcgi_script_name;
	fastcgi_param   SCRIPT_NAME             $fastcgi_script_name;
	fastcgi_param   PATH_INFO               $fastcgi_path_info;
	fastcgi_param   PATH_TRANSLATED         $document_root$fastcgi_path_info;
	fastcgi_param   REQUEST_URI             $request_uri;
	fastcgi_param   DOCUMENT_URI            $document_uri;
	fastcgi_param   DOCUMENT_ROOT           $document_root;
	fastcgi_param   SERVER_PROTOCOL         $server_protocol;

	fastcgi_param   GATEWAY_INTERFACE       CGI/1.1;
	fastcgi_param   SERVER_SOFTWARE         nginx/$nginx_version;

	fastcgi_param   REMOTE_ADDR             $remote_addr;
	fastcgi_param   REMOTE_PORT             $remote_port;
	fastcgi_param   SERVER_ADDR             $server_addr;
	fastcgi_param   SERVER_PORT             $server_port;
	fastcgi_param   SERVER_NAME             $server_name;

	fastcgi_param   HTTPS                   $https;

	# PHP only, required if PHP was built with --enable-force-cgi-redirect
	fastcgi_param   REDIRECT_STATUS         200;
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <WinSock2.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <sys/wait.h>
#define _strcmpi strcasecmp
#endif



#ifdef WIN32
#define PIPE_WIDTH 4096
void execute_cgi(FSPHANDLE client
				 , const char *path
				 , const char *method
				 , const char *query_string)
{
	printf_s("Not implemented yet\n");
}
#else
// Execute a CGI script.  Will need to set environment variables as appropriate.
void execute_cgi(FSPHANDLE client
				 , const char *path
				 , const char *method
				 , const char *query_string)
{
	char buf[1024];
	int	cgi_output[2];
	int cgi_input[2];
	pid_t pid;
	int status;
	int i;
	char c;
	int numchars = 1;
	int content_length = -1;

	buf[0] = 'A';
	buf[1] = '\0';
	if (_strcmpi(method, "GET") == 0)
	{
		/* read & discard headers */
		while ((numchars > 0) && strcmp("\n", buf))
		{
			numchars = ReadLine(client, buf, sizeof(buf));
		}
	}
	else // POST
	{
		numchars = ReadLine(client, buf, sizeof(buf));
		while ((numchars > 0) && strcmp("\n", buf))
		{
			buf[15] = '\0';
			if (_strcmpi(buf, "Content-Length:") == 0)
				content_length = atoi(&(buf[16]));
			numchars = ReadLine(client, buf, sizeof(buf));
		}
		if (content_length == -1)
		{
			bad_request(client);
			return;
		}
	}

	sprintf(buf, "HTTP/1.0 200 OK\r\n");
	send(client, buf, strlen(buf), 0);

	if (pipe(cgi_output) < 0)
	{
		cannot_execute(client);
		return;
	}

	if (pipe(cgi_input) < 0)
	{
		cannot_execute(client);
		return;
	}

	if ( (pid = fork()) < 0 )
	{
		cannot_execute(client);
		return;
	}
	if (pid == 0)  /* child: CGI script */
	{
		char meth_env[255];
		char query_env[255];
		char length_env[255];

		dup2(cgi_output[1], 1);
		dup2(cgi_input[0], 0);
		close(cgi_output[0]);
		close(cgi_input[1]);
		sprintf(meth_env, "REQUEST_METHOD=%s", method);
		putenv(meth_env);
		if (_strcmpi(method, "GET") == 0)
		{
			sprintf(query_env, "QUERY_STRING=%s", query_string);
			putenv(query_env);
		}
		else
		{   /* POST */
			sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
			putenv(length_env);
		}
		execl(path, path, NULL);
		exit(0);
		}
	else
	{    /* parent */
		close(cgi_output[1]);
		close(cgi_input[0]);
		if (_strcmpi(method, "POST") == 0)
		{
			for (i = 0; i < content_length; i++)
			{
			recv(client, &c, 1, 0);
			write(cgi_input[1], &c, 1);
			}
		}
		while (read(cgi_output[0], &c, 1) > 0)
			send(client, &c, 1, 0);

		close(cgi_output[0]);
		close(cgi_input[1]);
		waitpid(pid, &status, 0);
	}
}
#endif