#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "http_parser.h"

/*static void	  http_write(int, short, void *);
static char	 *generate_status_line(int);
static int	   on_url(http_parser*, const char*, size_t) ;
static int	   on_header_field(http_parser*, const char*, size_t);
static int	   on_header_value(http_parser*, const char*, size_t);
static int	   on_message_complete(http_parser*);
static void	  http_read(int, short, void *);
static int	   update_field(char**, const char *);
static void	  trim_string(char, char *);
static int	   open_listen(struct Mirrord *);
static void	  perform_events(struct Mirrord *);
static void	  mirrord_accept(int, short, void *);
static int	   parse_options(struct Mirrord *, int argc, char *[]);
static  __dead void usage(void);
int main(int, char *[]);*/

#define HTTP_HEADER_MAX_SIZE 81920

/*Response Codes*/
#define OK 200
#define BAD_REQUEST 400
#define FORBIDDEN 403
#define NOT_FOUND 404
#define METHOD_NOT_ALLOWED 405
#define INTERNAL_SERVER_ERROR 500

/*HTTP Method codes*/
#define GET 1
#define HEAD 2

/*Exit codes and messages*/
#define NO_FAIL 0
#define USAGE_FAIL 1
#define SOCKET_FAIL 2
#define BIND_FAIL 3
#define LISTEN_FAIL 4
#define DAEMONISE_FAIL 5
#define DIRECTORY_FAIL 6 
#define LOG_OPEN_FAIL 7
#define MEMORY_ALLOCATION_FAIL 8
#define ACCEPT_FAIL 9
#define EVENT_FAIL 10
#define MSG_READ_FAIL 11
#define EVENT_BUFFER_FAIL 12
#define GET_ADDRESS_INFO_FAIL 13

#define SOCKET_MSG "Socket creation or option setting failed"
#define BIND_MSG "Binding to socket failed"
#define LISTEN_MSG "Failed to listen"
#define DAEMONISE_MSG "Failed to daemonise"
#define DIRECTORY_MSG "Failed to access specified directory"
#define LOG_OPEN_FAIL_MSG "Failed to open specified log file"
#define ACCEPT_FAIL_MSG "Failed to properly accept connection or set options on accept socket"
#define EVENT_FAIL_MSG "Fail to add or delete a libevent event"

struct Mirrord {
	FILE *log;
	char *address;
	char *directory;
	char *port;
	char *logFilename;
	int ai_family;
	int listenSocket;
	bool daemonise;
};

struct HttpHeader {/*Use queue?*/
	struct HttpHeader *next;
	char *headerField;
	char *headerValue;
};

struct conn {
	struct event httpRead;
	struct event httpWrite;
	struct evbuffer *buf;
	struct http_parser *parser; 
	struct http_parser_settings *settings;
	struct HttpHeader *first;
	struct HttpHeader *current;
	char *url;
	char *httpVersion;
	char *replyHeaders;
	char *replyBody;
	char *statusLine;
	int httpMethod;
	int response;
};

__dead void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
	exit(USAGE_FAIL);
}

void
close_connection(struct conn *connection, int acceptSocket)
{
	struct HttpHeader *tmp, *current;
	
	current = connection->first;
	tmp = current;
	while (current != NULL) {
		tmp = current->next;
		free(current->headerField);
		free(current->headerValue);
		free(current);
		current = tmp;
	}
	
	evbuffer_free(connection->buf);
	if (event_del(&connection->httpRead) != 0)
		errx(EVENT_FAIL, "%s - %s", EVENT_FAIL_MSG, strerror(errno));
	if (event_del(&connection->httpWrite) != 0)
		errx(EVENT_FAIL, "%s - %s", EVENT_FAIL_MSG, strerror(errno));
	
	close(acceptSocket);
	free(connection->parser);
	free(connection->settings);
	free(connection->replyHeaders);
	free(connection->replyBody);
	free(connection->statusLine);
	free(connection);
}


void 
set_response_status(struct conn *connection, int responseCode)
{
	if (connection->response == OK) 
		connection->response = responseCode
}

char*
generate_status_line(int status, char *statusLine)
{
	char reason200[] = "HTTP/1.0 200 OK\r\n";
	char reason400[] = "HTTP/1.0 400 Bad Request\r\n";
	char reason403[] = "HTTP/1.0 403 Forbidden\r\n";
	char reason404[] = "HTTP/1.0 404 Not Found\r\n";
	char reason405[] = "HTTP/1.0 405 Method Not Allowed\r\n";
	char reason500[] = "HTTP/1.0 500 Internal Server Error\r\n";

	statusLine = calloc(80, sizeof(char));
	
	if (statusLine == NULL)
		return NULL;

	switch (status) {
	case OK:
		statusLine = reason200;
		break;
	case BAD_REQUEST:
		statusLine = reason400;
		break;
	case FORBIDDEN:
		statusLine = reason403;
		break;
	case NOT_FOUND:
		statusLine = reason404;
		break;
	case METHOD_NOT_ALLOWED:
		statusLine = reason405;
		break;
	case INTERNAL_SERVER_ERROR:
		statusLine = reason500;
		break;
	}

	return statusLine;		
}


char*
get_body(FILE *webFile, struct conn *connection, char *body)
{
	long offset, bodySize;

	body = NULL;
	offset = 0L;

	if (fseek(webFile, offset, SEEK_END) != 0)
		return NULL;

	if ((bodySize = ftell(webFile)) == -1)
		return NULL;

	if ((body = calloc(bodySize + 1, sizeof(char))) == NULL) {
		warnx("%s", strerror(errno));
		return NULL;
	}

	if (fseek(webFile, offset, SEEK_SET) != 0)
		return NULL;

	if ((fread(body, sizeof(char), bodySize, webFile)) == 0)
		return NULL; // DETECT ERROR

	return body;
}

void
http_write(int acceptSocket, short revents, void *c)
{
	struct conn *connection = c;
	struct stat fileStats;
	struct tm fileTime;
	time_t currentTime;
	FILE *webFile;
	char *url, *statusLine, *headers, *body, httpTime[80], contentLength[80], lastModified[80];
	int headersLength;
	
	char serverLine[] = "Server: mirrord/s4174126\r\n";
	char connectionLine[] = "Connection: close\r\n";
	char headerEnd[] = "\r\n";
	
	headersLength = HTTP_HEADER_MAX_SIZE;	   
	url = connection->url;
	
	headers = calloc(headersLength, sizeof(char));
	
	webFile = NULL;

	if (url == NULL || strlen(url) == 0)
		set_response_status(connection, NOT_FOUND);
	else 
		webFile = fopen(url, "r");

	if (webFile == NULL) {
		switch (errno) {
		case EACCES:
			set_response_status(connection, FORBIDDEN);
			break;
		default:
			set_response_status(connection, NOT_FOUND);
		}
	} else { 
		if (fstat(fileno(webFile), &fileStats) != 0) 
			set_response_status(connection, INTERNAL_SERVER_ERROR);
		if ((body = get_body(webFile, connection, body)) == NULL)
			set_response_status(connection, INTERNAL_SERVER_ERROR);
	}
	
	statusLine = generate_status_line(connection->response, statusLine);
	
	if (headers == NULL || statusLine == NULL) {
		warnx("%s", strerror(errno));
		close_connection(connection, acceptSocket);
		return;
	}
	
	connection->statusLine = statusLine;
	strlcpy(headers, statusLine, 80);
	
	time(&currentTime);
	strftime(httpTime, 79, "Date: %a, %d %b %Y %X %Z\r\n", gmtime(&currentTime));
	strlcat(headers, httpTime, headersLength);
	
	strlcat(headers, serverLine, headersLength);
	strlcat(headers, connectionLine, headersLength);   

	if (connection->response == OK) {
		snprintf(contentLength, 79, "Content-Length: %zd\r\n", strlen(body) - 1);
		gmtime_r(&(fileStats.st_mtime), &fileTime);
		strftime(lastModified, 79, "Last-Modified: %a, %d %b %Y %X %Z\r\n", &fileTime);
		strlcat(headers, contentLength, headersLength);
		strlcat(headers, lastModified, headersLength);
	}
	
	strlcat(headers, headerEnd, headersLength);

	connection->replyHeaders = headers;
	connection->replyBody = body;

	if (evbuffer_add(connection->buf, headers, strlen(headers)) != 0) {
		warnx(%s", strerror(errno));
		close_connection(connection, acceptSocket);
		return;
	}

	if (body != NULL && connection->httpMethod == GET) {
		if (evbuffer_add(connection->buf, body, strlen(body)) != 0) {
			warnx("%s", strerror(errno));
			close_connection(connection, acceptSocket);
			return;
		}
	}

	if (evbuffer_write(connection->buf, acceptSocket) == -1)
		warnx("%s", strerror(errno));
	
	close_connection(connection, acceptSocket);
}

void 
trim_string(char removeAfter, char *string)
{
	int length, i;
	
	length = strlen(string);
	i = 0;

	while (i < length) {
		if (string[i] == removeAfter) {
			while (i < length) {
				string[i] = 0;
				i++;
			}
		}
		i++;
	}
}

int
on_message_complete(http_parser *parser)
{
	struct conn *connection = parser->data;
	struct HttpHeader *current;

	trim_string(' ', connection->url);
	 
	if (connection->url[0] == '/')
		connection->url++;
	else
		set_response_status(connection, BAD_REQUEST);
	
	connection->httpMethod = parser->method;

	if (parser->http_major != 1 && parser->http_minor != 0)
		set_response_status(connection, BAD_REQUEST);
	 
	current = connection->first;
	 
	while (current != NULL) {
		trim_string(':', current->headerField);
		trim_string('\r', current->headerValue);
		current = current->next;
	}

	if (parser->method != GET && parser->method != HEAD)
		set_response_status(connection, METHOD_NOT_ALLOWED);

	return 0;
}


int
update_field(char **field, const char *newData, struct conn *connection)
{
	char *tmpField, *newField;
	int oldLength, newLength;
	
	newLength = strlen(newData);

	if (*field == NULL) {
		newField = calloc((newLength + 1), sizeof(char));
		if (newField == NULL) {
			set_response_status(connection, INTERNAL_SERVER_ERROR);
			return -1;
		} else
			strlcpy(newField, newData, (newLength + 1));
	} else {
		oldLength = strlen(*field);
		tmpField = realloc(*field, (newLength + oldLength + 1) * sizeof(char));
		if (tmpField == NULL) {
			set_response_status(connection, INTERNAL_SERVER_ERROR);
			return -1;
		} else
			strlcat(*field, newData, (newLength + oldLength + 1));
	}

	*field = newField;
	return 0;
}

int
on_header_field(http_parser *parser, const char *at, size_t length)
{
	struct conn *connection = parser->data;
	struct HttpHeader *header;

	if (connection->first == NULL) {
		/*First Header*/
		if ((header = calloc(1, sizeof(header))) == NULL) {
			set_response_status(connection, INTERNAL_SERVER_ERROR);
			return -1;
		}
		
		header->headerField = NULL;
		header->headerValue = NULL;
		header->next = NULL;
		
		connection->first = header;
		connection->current = header;
		
	} else if (connection->current->headerValue != NULL) {
		/*
		* If the headerValue contains text, and the on header field 
		* function is called, it's the start of a new header.
		*/
		if ((header = calloc(1, sizeof(header))) == NULL) { 
			set_response_status(connection, INTERNAL_SERVER_ERROR);
			return -1;
		}
		header->headerField = NULL;
		header->headerValue = NULL;
		header->next = NULL;
		connection->current->next = header;
		connection->current = header;
	}
	return update_field(&connection->current->headerField, at, connection);
}

int
on_header_value(http_parser *parser, const char *at, size_t length)
{
	struct conn *connection = parser->data;
	return update_field(&connection->current->headerValue, at, connection);
}

int
on_url(http_parser *parser, const char *at, size_t length)
{
	struct conn *connection = parser->data;
	return update_field(&connection->url, at, connection);
}

void
http_read(int acceptSocket, short revents, void *c)
{
	struct conn *connection = c;
	char buf[HTTP_HEADER_MAX_SIZE];
	size_t nparsed;
	int len;

	len = evbuffer_read(connection->buf, acceptSocket, HTTP_HEADER_MAX_SIZE);

	switch (len) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			return;
		case ECONNRESET:
			break;
		default:
			warnx("%s", strerror(errno));
			break;
		}
		/* FALLTHROUGH */
	case 0:
		close_connection(connection);
		return;
	default:
		break;
	}

	if (evbuffer_remove(connection->buf, buf, HTTP_HEADER_MAX_SIZE) == -1)
		set_response_status(connection, INTERNAL_SERVER_ERROR);
	else {
		nparsed = http_parser_execute(connection->parser, connection->settings, buf, len);
		
		if (len != nparsed) 
			set_response_status(connection, BAD_REQUEST);
	}

	if (event_add(&connection->httpWrite, NULL) != 0)
		errx(EVENT_FAIL, "%s - %s", EVENT_FAIL_MSG, strerror(errno));
}

void setup_http_parser(struct conn *connection) 
{
	http_parser_settings *settings = calloc(1, sizeof(http_parser_settings));
	http_parser *parser = calloc(1, sizeof(http_parser));
	
	if (settings == NULL || parser == NULL) 
		errx(MEMORY_ALLOCATION_FAIL, "%s", strerror(errno));

	http_parser_init(parser, HTTP_REQUEST);
	parser->data = connection;

	http_parser_settings_init(settings);

	settings->on_url = on_url;
	settings->on_header_field = on_header_field;
	settings->on_header_value = on_header_value;
	settings->on_message_complete = on_message_complete;
	
	connection->parser = parser;
	connection->settings = settings;
}

void 
setup_connection(struct conn *connection) {
	connection->url = NULL;
	connection->httpVersion = NULL;
	connection->first = NULL;
	connection->current = NULL;
	connection->response = OK; /* Will be changed if there is a problem */
	connection->replyHeaders = NULL;
	connection->replyBody = NULL;
	connection->httpRead = NULL;
	connection->httpWrite = NULL;
	connection->parser = NULL;
	connection->settings = NULL;
	connection->buf = NULL;
}

void
mirrord_accept(int listenSocket, short revents, void *null)
{
	struct sockaddr_storage ss;
	struct conn *connection;
	socklen_t socklen;
	int acceptSocket, on;
	
	socklen = sizeof(ss);
	on = 1;

	acceptSocket = accept(listenSocket, (struct sockaddr *)&ss, &socklen);
	if (acceptSocket == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		default:
			errx(ACCEPT_FAIL, "%s - %s", ACCEPT_FAIL_MSG, strerror(errno));
		}
	}

	if (ioctl(acceptSocket, FIONBIO, &on) == -1) 
		errx(ACCEPT_FAIL, "%s - %s", ACCEPT_FAIL_MSG, strerror(errno));
	
	connection = calloc(1, sizeof(*connection));
	if (connection == NULL) {
		warnx("%s", strerror(errno));
		close(acceptSocket);
		return;
	}
	
	setup_connection(connection);

	connection->buf = evbuffer_new();
	if (connection->buf == NULL) {
		warnx("%s", strerror(errno));
		free(connection);
		close(acceptSocket);
		return;
	}
	
	setup_http_parser(connection);

	printf("Accepted new connection: %d\n", acceptSocket);
	
	event_set(&connection->httpRead, acceptSocket, EV_READ | EV_PERSIST, http_read, connection);
	event_set(&connection->httpWrite, acceptSocket, EV_WRITE, http_write, connection);
	if (event_add(&connection->httpRead, NULL) != 0) 
		errx(EVENT_FAIL, "%s - %s", EVENT_FAIL_MSG, strerror(errno));
		
}

void
perform_events(struct Mirrord *m)
{
	struct event event;
	
	event_init();
	event_set(&event, m->listenSocket, EV_READ | EV_PERSIST, mirrord_accept, NULL);
	if (event_add(&event, 0) != 0)
		errx(EVENT_FAIL, "%s - %s", EVENT_FAIL_MSG, strerror(errno));	
	event_dispatch();
}

int
open_listen(struct Mirrord *m)
{
	struct addrinfo hints; 
	struct addrinfo *res;
	int fd, optVal, on, addrinfoErr;

	res = 0;
	
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_family = m->ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

	if ((addrinfoErr = getaddrinfo(m->address, m->port, &hints, &res)) != 0) {
		errx(GET_ADDRESS_INFO_FAIL, "Error with address or port - %s", gai_strerror(addrinfoErr));
	}

	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
		errx(SOCKET_FAIL, "%s - %s", SOCKET_MSG, strerror(errno));

	optVal = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(int)) < 0)
		errx(SOCKET_FAIL, "%s - %s", SOCKET_MSG, strerror(errno));

	if (bind(fd, res->ai_addr, res->ai_addrlen) < 0)
		errx(BIND_FAIL, "%s - %s", BIND_MSG, strerror(errno));
		
	on = 1;
	if (ioctl(fd, FIONBIO, &on) == -1) 
		errx(SOCKET_FAIL, "%s - %s", SOCKET_MSG, strerror(errno));

	freeaddrinfo(res);

	if (listen(fd, SOMAXCONN) < 0) 
		errx(LISTEN_FAIL, "%s - %s", LISTEN_MSG, strerror(errno));

	printf("Listening on port: %s", m->port);
	if (m->address != NULL)
		printf(", and address: %s", m->address);
	printf("\n");
		
	return fd;
}

int
parse_options(struct Mirrord *m, int argc, char *argv[])
{
	char option, *optstring;
	extern char *optarg;
	extern int opterr, optind;
	
	optstring = "46da:l:p:";

	m->log = NULL;
	m->address = 0;
	m->daemonise = true;
	m->port = "www";
	m->logFilename = NULL;
	m->ai_family = AF_UNSPEC;

	opterr = 1;

	while ((option = getopt(argc, argv, optstring)) != -1) {
		switch (option) {
		case '4':
			m->ai_family = AF_INET;
			break;
		case '6':
			m->ai_family = AF_INET6;
			break;
		case 'd':
			m->daemonise = false;
			break;
		case 'a':
			m->logFilename = optarg;
			break;
		case 'l':
			m->address = optarg;
			break;
		case 'p':
			m->port = optarg;
			break;
		default:
			usage();
		}
	}
	return optind;
}

/* 
 * All major routines should have a comment briefly describing what 
 * they do.  The comment before the "main" routine should describe 
 * what the program does. 
 */ 
int 
main(int argc, char *argv[]) 
{
	struct Mirrord *m = NULL;
	int optind;

	if ((m = calloc(1, sizeof(*m))) == NULL) 
		errx(MEMORY_ALLOCATION_FAIL, "%s", strerror(errno));

	optind = parse_options(m, argc, argv);

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	m->directory = argv[argc - 1];

	if (m->logFilename) {
		if ((m->log = fopen(m->logFilename, "w")) == NULL) 
			errx(LOG_OPEN_FAIL, "%s - %s", LOG_OPEN_FAIL_MSG, strerror(errno));
	}
	
	if (m->daemonise) {
		if (daemon(1, 0) != 0)
			errx(DAEMONISE_FAIL, "%s - %s", DAEMONISE_MSG, strerror(errno));
	} 

	if ((chdir(m->directory)) < 0) 
		errx(DIRECTORY_FAIL, "%s - %s", DIRECTORY_MSG, strerror(errno));
	
	m->listenSocket = open_listen(m);
	
	perform_events(m);
	
	/* Not Reached */
	fclose(m->log);
	free(m);
	
	return 0;
}


